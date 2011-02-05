{-# LANGUAGE OverloadedStrings #-}
module Crypto.PasswordStore (makePassword, verifyPassword, strengthen) where

import qualified Crypto.Hash.SHA256 as H
import qualified Data.ByteString.Char8 as B
import Data.ByteString.Char8 (ByteString)
import Data.ByteString.Base64 (encode, decodeLenient)
import System.IO
import System.Random
import System.IO.Error (catch)

-- | PBKDF1 key-derivation function. Takes a password, a salt, and a
-- number of iterations. The number of iterations should be at least
-- 1000, and probably more. 5000 is a reasonable number, computing
-- almost instantaneously. This will give a 32-byte 'ByteString' as
-- output. Both the salt and this 32-byte key should be stored in the
-- password file. When a user wishes to authenticate a password, just
-- pass it and the salt to this function, and see if the output
-- matches.
pbkdf1 :: ByteString -> ByteString -> Int -> ByteString
pbkdf1 password salt iter = hashRounds first_hash (iter + 1)
    where first_hash = H.finalize $ H.init `H.update` password `H.update` salt

-- | Hash a ByteString for a given number of rounds. The number of
-- rounds is 0 or more. If the number of rounds specified is 0, the
-- ByteString will be returned unmodified.
hashRounds :: ByteString -> Int -> ByteString
hashRounds bs rounds = (iterate H.hash bs) !! rounds

-- | Generate a base64-encoded salt from 128 bits of data from $/dev/urandom$,
-- with the system RNG as a fallback. The result is 24 characters long.
genSalt :: IO ByteString
genSalt = catch genSaltDevURandom (\_ -> genSaltSysRandom)

-- | Generate a salt from @/dev/urandom@.
genSaltDevURandom = withFile "/dev/urandom" ReadMode $ \h -> do
                      rawSalt <- B.hGet h 16
                      return $ encode rawSalt

-- | Generate a salt from 'System.Random'.
genSaltSysRandom = randomChars >>= return . encode . B.pack
    where randomChars = sequence $ replicate 16 $ randomRIO ('\NUL', '\255')


-- High level API

-- Format: "sha256|strength|salt|hash", where strength is an unsigned
-- int, salt is a base64-encoded 16-byte random number, and hash is a
-- base64-encoded hash value.

-- | Hash a password with a given strength (12 is a good
-- default). Generates a salt using high-quality randomness from
-- @/dev/urandom@, which is included in the hashed output. The output
-- of this function can be written directly to a password file or
-- database.
makePassword :: ByteString -> Int -> IO ByteString
makePassword password strength = do
  salt <- genSalt
  let hash = encode $ pbkdf1 password salt (2^strength)
  return $ writePwHash (strength, salt, hash)

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
-- times. @strengthen pwHash new_strength@ will return a new password
-- hash with strength at least @new_strength@. If the password hash
-- already has strength greater than or equal to @new_strength@, then
-- it is returned unmodified. If the password hash is invalid and does
-- not parse, it will be returned without comment.
-- 
-- This function can be used to periodically update your password
-- database when computers get faster, in order to keep up with
-- Moore's law. This isn't hugely important, but it's a good idea.
strengthen :: ByteString -> Int -> ByteString
strengthen pwHash newstr = 
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

-- | Encode a password hash, from a @(strength, salt, hash)@ tuple,
-- where strength is an 'Int', and both @salt@ and @hash@ are
-- base64-encoded 'ByteString's.
writePwHash :: (Int, ByteString, ByteString) -> ByteString
writePwHash (strength, salt, hash) =
    B.intercalate "|" ["sha256", B.pack (show strength), salt, hash]
