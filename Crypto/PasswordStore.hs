{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Crypto.PasswordStore
-- Copyright   : (c) Peter Scott, 2011
-- License     : BSD-style
--
-- Maintainer  : pjscott@iastate.edu
-- Stability   : experimental
-- Portability : portable
--
-- Securely store hashed, salted passwords. If you need to store and verify
-- passwords, there are many wrong ways to do it, most of them all too
-- common. Some people store users' passwords in plain text. Then, when an
-- attacker manages to get their hands on this file, they have the passwords for
-- every user's account. One step up, but still wrong, is to simply hash all
-- passwords with SHA1 or something. This is vulnerable to rainbow table and
-- dictionary attacks. One step up from that is to hash the password along with
-- a unique salt value. This is vulnerable to dictionary attacks, since guessing
-- a password is very fast. The right thing to do is to use a slow hash
-- function, to add some small but significant delay, that will be negligible
-- for legitimate users but prohibitively expensive for someone trying to guess
-- passwords by brute force. That is what this library does. It iterates a
-- SHA256 hash, with a random salt, a few thousand times. This scheme is known
-- as PBKDF1, and is generally considered secure; there is nothing innovative
-- happening here.
--
-- The API here is very simple. What you store are called /password hashes/.
-- They are strings (technically, ByteStrings) that look like this:
--
-- > "sha256|12|Ge9pg8a/r4JW356Uux2JHg==|Fdv4jchzDlRAs6WFNUarxLngaittknbaHFFc0k8hAy0="
--
-- Each password hash shows the algorithm, the strength (more on that later),
-- the salt, and the hashed-and-salted password. You store these on your server,
-- in a database, for when you need to verify a password. You make a password
-- hash with the 'makePassword' function. Here's an example:
--
-- > >>> makePassword "hunter2" 12
-- > "sha256|12|lMzlNz0XK9eiPIYPY96QCQ==|1ZJ/R3qLEF0oCBVNtvNKLwZLpXPM7bLEy/Nc6QBxWro="
--
-- This will hash the password @\"hunter2\"@, with strength 12, which is a good
-- default value. The strength here determines how long the hashing will
-- take. When doing the hashing, we iterate the SHA256 hash function
-- @2^strength@ times, so increasing the strength by 1 makes the hashing take
-- twice as long. When computers get faster, you can bump up the strength a
-- little bit to compensate. You can strengthen existing password hashes with
-- the 'strengthenPassword' function. Note that 'makePassword' needs to generate
-- random numbers, so its return type is 'IO' 'ByteString'. If you want to avoid
-- the 'IO' monad, you can generate your own salt and pass it to
-- 'makePasswordSalt'.
--
-- Your strength value should not be less than 10, and 12 is a good default
-- value at the time of this writing, in 2011.
--
-- Once you've got your password hashes, the second big thing you need to do
-- with them is verify passwords against them. When a user gives you a password,
-- you compare it with a password hash using the 'verifyPassword' function:
--
-- > >>> verifyPassword "wrong guess" passwordHash
-- > False
-- > >>> verifyPassword "hunter2" passwordHash
-- > True
--
-- These two functions are really all you need. If you want to make existing
-- password hashes stronger, you can use 'strengthenPassword'. Just pass it an
-- existing password hash and a new strength value, and it will return a new
-- password hash with that strength value, which will match the same password as
-- the old password hash.
--

module Crypto.PasswordStore (
        -- * Registering and verifying passwords
        makePassword,           -- :: ByteString -> Int -> IO ByteString
        makePasswordSalt,       -- :: ByteString -> ByteString -> Int -> ByteString
        verifyPassword,         -- :: ByteString -> ByteString -> Bool

        -- * Updating password hash strength
        strengthenPassword,     -- :: ByteString -> Int -> ByteString
        passwordStrength,       -- :: ByteString -> Int

        -- * Utilities
        isPasswordFormatValid,  -- :: ByteString -> Bool
        genSaltIO,              -- :: IO ByteString
        genSaltRandom           -- :: (RandomGen b) => b -> (ByteString, b)
  ) where

import qualified Crypto.Hash.SHA256 as H
import qualified Data.ByteString.Char8 as B
import Data.ByteString.Char8 (ByteString)
import Data.ByteString.Base64 (encode, decodeLenient)
import System.IO
import System.Random

---------------------
-- Cryptographic base
---------------------

-- | PBKDF1 key-derivation function. Takes a password, a salt, and a number of
-- iterations. The number of iterations should be at least 1000, and probably
-- more. 5000 is a reasonable number, computing almost instantaneously. This
-- will give a 32-byte 'ByteString' as output. Both the salt and this 32-byte
-- key should be stored in the password file. When a user wishes to authenticate
-- a password, just pass it and the salt to this function, and see if the output
-- matches.
pbkdf1 :: ByteString -> ByteString -> Int -> ByteString
pbkdf1 password salt iter = hashRounds first_hash (iter + 1)
    where first_hash = H.finalize $ H.init `H.update` password `H.update` salt

-- | Hash a ByteString for a given number of rounds. The number of rounds is 0
-- or more. If the number of rounds specified is 0, the ByteString will be
-- returned unmodified.
hashRounds :: ByteString -> Int -> ByteString
hashRounds bs rounds = (iterate H.hash bs) !! rounds

-- | Generate a base64-encoded salt from 128 bits of data from @\/dev\/urandom@,
-- with the system RNG as a fallback. The result is 24 characters long.
genSaltIO :: IO ByteString
genSaltIO = catch genSaltDevURandom (\_ -> genSaltSysRandom)

-- | Generate a salt from @\/dev\/urandom@.
genSaltDevURandom :: IO ByteString
genSaltDevURandom = withFile "/dev/urandom" ReadMode $ \h -> do
                      rawSalt <- B.hGet h 16
                      return $ encode rawSalt

-- | Generate a salt from 'System.Random'.
genSaltSysRandom :: IO ByteString
genSaltSysRandom = randomChars >>= return . encode . B.pack
    where randomChars = sequence $ replicate 16 $ randomRIO ('\NUL', '\255')

-----------------------
-- Password hash format
-----------------------

-- Format: "sha256|strength|salt|hash", where strength is an unsigned int, salt
-- is a base64-encoded 16-byte random number, and hash is a base64-encoded hash
-- value.

-- | Try to parse a password hash.
readPwHash :: ByteString -> Maybe (Int, ByteString, ByteString)
readPwHash pw | length broken /= 4
                || algorithm /= "sha256"
                || B.length salt /= 24
                || B.length hash /= 44 = Nothing
              | otherwise = case B.readInt strBS of
                              Just (strength, _) -> Just (strength, salt, hash)
                              Nothing -> Nothing
    where broken = B.split '|' pw
          [algorithm, strBS, salt, hash] = broken

-- | Encode a password hash, from a @(strength, salt, hash)@ tuple, where
-- strength is an 'Int', and both @salt@ and @hash@ are base64-encoded
-- 'ByteString's.
writePwHash :: (Int, ByteString, ByteString) -> ByteString
writePwHash (strength, salt, hash) =
    B.intercalate "|" ["sha256", B.pack (show strength), salt, hash]

-----------------
-- High level API
-----------------

-- | Hash a password with a given strength (12 is a good default). The output of
-- this function can be written directly to a password file or
-- database. Generates a salt using high-quality randomness from
-- @\/dev\/urandom@ or (if that is not available) 'System.Random', which is
-- included in the hashed output.
makePassword :: ByteString -> Int -> IO ByteString
makePassword password strength = do
  salt <- genSaltIO
  return $ makePasswordSalt password salt strength

-- | Hash a password with a given strength (12 is a good default), using a given
-- salt. The output of this function can be written directly to a password file
-- or database. Example:
--
-- > >>> makePasswordSalt "hunter2" "72cd18b5ebfe6e96" 12
-- > "sha256|12|72cd18b5ebfe6e96|Xkki10Vus/a2SN/LgCVLTT5R30lvHSCCxH6QboV+U3E="
makePasswordSalt :: ByteString -> ByteString -> Int -> ByteString
makePasswordSalt password salt strength = writePwHash (strength, salt, hash)
    where hash = encode $ pbkdf1 password salt (2^strength)

-- | Verify a password given by the user against a stored password
-- hash. Returns 'True' if the given password is correct, and 'False'
-- if it is not.
verifyPassword :: ByteString -> ByteString -> Bool
verifyPassword userInput pwHash =
    case readPwHash pwHash of
      Nothing -> False
      Just (strength, salt, goodHash) ->
          (encode $ pbkdf1 userInput salt (2^strength)) == goodHash

-- | Try to strengthen a password hash, by hashing it some more
-- times. @'strengthenPassword' pwHash new_strength@ will return a new password
-- hash with strength at least @new_strength@. If the password hash already has
-- strength greater than or equal to @new_strength@, then it is returned
-- unmodified. If the password hash is invalid and does not parse, it will be
-- returned without comment.
--
-- This function can be used to periodically update your password database when
-- computers get faster, in order to keep up with Moore's law. This isn't hugely
-- important, but it's a good idea.
strengthenPassword :: ByteString -> Int -> ByteString
strengthenPassword pwHash newstr =
    case readPwHash pwHash of
      Nothing -> pwHash
      Just (oldstr, salt, hashB64) ->
          if oldstr < newstr then
              writePwHash (newstr, salt, newHash)
          else
              pwHash
          where newHash = encode $ hashRounds hash extraRounds
                extraRounds = (2^newstr) - (2^oldstr)
                hash = decodeLenient hashB64

-- | Return the strength of a password hash.
passwordStrength :: ByteString -> Int
passwordStrength pwHash = case readPwHash pwHash of
                            Nothing               -> 0
                            Just (strength, _, _) -> strength

------------
-- Utilities
------------

-- | Is the format of a password hash valid? Attempts to parse a given password
-- hash. Returns 'True' if it parses correctly, and 'False' otherwise.
isPasswordFormatValid :: ByteString -> Bool
isPasswordFormatValid = (/=Nothing) . readPwHash

-- | Generate a base64-encoded salt from 128 bits of data taken from a given
-- random number generator. The result is 24 characters long. Returns the salt
-- and the updated random number generator.
genSaltRandom :: (RandomGen b) => b -> (ByteString, b)
genSaltRandom g = (salt, g')
    where rands g 0 = []
          rands g n = (a, g') : rands g' (n-1)
              where (a, g') = randomR ('\NUL', '\255') g
          salt = encode $ B.pack $ map fst (rands g 16)
          g'   = snd $ last (rands g 16)

