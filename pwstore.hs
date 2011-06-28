module Main (main) where

import Paths_pwstore_fast (version)

import Control.Applicative ((*>), (<*))
import Control.Monad (when)
import Crypto.PasswordStore (genSaltIO, makeSalt, makePasswordSalt)
import qualified Data.ByteString.Char8 as B
import Data.Version (showVersion)
import System.Console.CmdArgs
import System.Environment (getProgName)
import System.Exit (exitFailure)
import System.IO (stdin, stdout, hFlush, hIsTerminalDevice, hSetEcho)

-- | Command line options.
data Options = Options { strength :: Int
                       , password :: Maybe String
                       , salt :: Maybe String
                       }
             deriving (Show, Data, Typeable)

-- | Build the CmdArgs option parser.
options :: String -> Mode (CmdArgs Options)
options progname =
  cmdArgsMode_ $ record Options{}
    [ strength := 12
      += help "Strength value, default is 12"
    , password := Nothing
      += help "Password to hash, will be asked for if missing"
      += typ "PASSWORD"
      += explicit
      += name "password"
    , salt := Nothing
      += help "Hash salt, a random salt is used if missing"
      += typ "SALT"
      += explicit
      += name "salt"
    ]
    += program progname
    += summary (progname ++ " " ++ showVersion version)
    += details [ "The " ++ progname ++ " program generates salted password hashes suitable for storage."
               , ""
               , "Note, this program assumes the use of ASCII characters in salts and passwords."
               ]
    += helpArg []
    += versionArg []

-- | IO action that reads a password from standard input.  Terminal
-- echoing is disabled while reading.
getPassword :: IO B.ByteString
getPassword =
  do isTerminal <- hIsTerminalDevice stdin
     if isTerminal
       then putStr "Password: "
            *> hFlush stdout
            *> hSetEcho stdin False
            *> B.getLine
            <* hSetEcho stdin True
            <* putStrLn ""
       else B.getLine

main :: IO ()
main =
  do progname <- getProgName
     Options{..} <- cmdArgsRun . options $ progname

     when (strength < 1) $
       putStrLn "Strength must be positive" >> exitFailure

     when (maybe False ((< 8) . length) salt) $
       putStrLn "Salt must be 8 characters or longer." >> exitFailure

     password' <- maybe getPassword (return . B.pack) password
     salt' <- maybe genSaltIO (return . makeSalt . B.pack) salt

     B.putStrLn $ makePasswordSalt password' salt' strength
