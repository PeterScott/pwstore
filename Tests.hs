{-# LANGUAGE OverloadedStrings #-}
import Test.HUnit
import Crypto.PasswordStore
import qualified Data.ByteString.Char8 as B
import Data.ByteString.Char8 (ByteString)
import System.Random

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

test_makePasswordSalt1 = makePasswordSalt "hunter2" (makeSalt "72cd18b5ebfe6e96") 12 ~?= pw
    where pw = "sha256|12|NzJjZDE4YjVlYmZlNmU5Ng==|M17VU2ciK8VaKyyDfVeGHS5eiLAuiStg/Y647B+Y4aE="
test_makePasswordSalt2 = makePasswordSalt "foo" (makeSalt "slithy toves") 14 ~?= pw
    where pw = "sha256|14|c2xpdGh5IHRvdmVz|wgSFKj3EH76xbjtIdIhqpWzLbBkkDmo76xjobuFuRFo="
test_makePasswordSalt = TestList [ "test make password salt 1" ~: test_makePasswordSalt1
                                 , "test make password salt 2" ~: test_makePasswordSalt2
                                 ]

test_passwordStrength1 = passwordStrength pwh ~?= 12
test_passwordStrength2 = passwordStrength pws ~?= 14
test_passwordStrength3 = passwordStrength pww ~?= 4
test_passwordStrength = TestList [ "test password strength 12" ~: test_passwordStrength1
                                 , "test password strength 14" ~: test_passwordStrength2
                                 , "test password strength 4"  ~: test_passwordStrength3
                                 ]

test_genSaltRandom = "test genSaltRandom" ~: testIt
    where testIt = TestList [show salt1 ~?= "SaltBS \"z0+F+uw3fh8SsyUTFAa4YQ==\"",
                             show salt2 ~?= "SaltBS \"tyeByF5Y9NY0ugrCR+6Ymw==\""]
          (salt1, g) = genSaltRandom (mkStdGen 42)
          (salt2, _) = genSaltRandom g

test_isPasswordFormatValid1 = isPasswordFormatValid pwh ~?= True
test_isPasswordFormatValid2 = isPasswordFormatValid pww ~?= True
test_isPasswordFormatValid3 = isPasswordFormatValid "foo" ~?= False
test_isPasswordFormatValid4 = isPasswordFormatValid (pww `B.append` "|foo") ~?= False
test_isPasswordFormatValid = TestList [test_isPasswordFormatValid1,
                                       test_isPasswordFormatValid2,
                                       test_isPasswordFormatValid3,
                                       test_isPasswordFormatValid4]

test_strengthenPassword = strengthenPassword (mk 5) 10 ~?= (mk 10)
    where pwd = "mypassword"
          salt = makeSalt "not a proper salt"
          mk = makePasswordSalt pwd salt

tests = TestList [ test_verifyPassword
                 , test_passwordStrength
                 , test_makePasswordSalt
                 , test_makePassword
                 , test_genSaltRandom
                 , test_isPasswordFormatValid
                 , test_strengthenPassword
                 ]
main = runTestTT tests
