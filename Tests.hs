{-# LANGUAGE OverloadedStrings #-}
import Test.HUnit
import Crypto.PasswordStore
import qualified Data.ByteString.Char8 as B
import Data.ByteString.Char8 (ByteString)

pwh = "sha256|12|lMzlNz0XK9eiPIYPY96QCQ==|1ZJ/R3qLEF0oCBVNtvNKLwZLpXPM7bLEy/Nc6QBxWro="
pws = "sha256|14|m646oLe3PC+v+x4hGf8Ltg==|PxRNeoEp2w590olNP9JZVy9DB7gmcUJ1zgGoavYDoMA="
pww = "sha256|4|vTZ1vZezq4ljB0DemS76jg==|8m5/LfqaLDL05RaTVeZ8SpqQ3DNq7EJUwwrA/6G2+/o="

test_verifyPassword1 = verifyPassword "hunter2" pwh ~?= True
test_verifyPassword2 = verifyPassword "hunter3" pwh ~?= False
test_verifyPassword3 = verifyPassword "" pwh        ~?= False
test_verifyPassword = TestList [ "test verify 'hunter2'" ~: test_verifyPassword1
                               , "test verify 'hunter3'" ~: test_verifyPassword2
                               , "test verify ''"        ~: test_verifyPassword3
                               ]

-- Also tests strengthenPassword
test_makePassword = TestLabel "test makePassword" $ TestCase $ do
                      pw1 <- makePassword "foo bar baz" 10
                      pw2 <- makePassword "hello" 12
                      pw3 <- makePassword "password" 14
                      pw4 <- makePassword "hello" 12
                      (pw2 /= pw4) @?= True
                      verifyPassword "foo bar baz" pw1  @?= True
                      verifyPassword "not correct" pw1  @?= False
                      verifyPassword "hello" pw2        @?= True
                      verifyPassword "world" pw2        @?= False
                      verifyPassword "password" pw3     @?= True
                      verifyPassword "" pw3             @?= False
                      let pw1' = strengthenPassword pw1 11
                          pw2' = strengthenPassword pw2 13
                          pw3' = strengthenPassword pw3 8 -- Unmodified
                      passwordStrength pw1' @?= 11
                      passwordStrength pw2' @?= 13
                      passwordStrength pw3' @?= 14
                      verifyPassword "foo bar baz" pw1' @?= True
                      verifyPassword "not correct" pw1' @?= False
                      verifyPassword "hello" pw2'       @?= True
                      verifyPassword "world" pw2'       @?= False
                      verifyPassword "password" pw3'    @?= True
                      verifyPassword "" pw3'            @?= False

test_passwordStrength1 = passwordStrength pwh ~?= 12
test_passwordStrength2 = passwordStrength pws ~?= 14
test_passwordStrength3 = passwordStrength pww ~?= 4
test_passwordStrength = TestList [ "test password strength 12" ~: test_passwordStrength1
                                 , "test password strength 14" ~: test_passwordStrength2
                                 , "test password strength 4"  ~: test_passwordStrength3
                                 ]

tests = TestList [ test_verifyPassword
                 , test_passwordStrength
                 , test_makePassword
                 ]
main = runTestTT tests
