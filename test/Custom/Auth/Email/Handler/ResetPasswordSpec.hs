{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts  #-}

module Custom.Auth.Email.Handler.ResetPasswordSpec (spec) where

import qualified Data.Text            as T
import           Database.Persist.Sql
import           TestImport

spec :: Spec
spec = withApp $

  describe "Post request to http://localhost:3000/auth/plugin/email/reset-password" $ do

    let getCheckR = do
          TestImport.get ("http://localhost:3000/auth/check" :: Text)
          statusIs 200

    let basicRequestBuilder encoded encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken = do
          setMethod "POST"
          setUrl $ AuthR $ PluginR "email" ["reset-password", encryptedAndUrlEncodedUserId, encryptedAndUrlEncodedVerificationToken]
          setRequestBody encoded
          addRequestHeader ("Content-Type", "application/json")

    let postResetPasswordR encoded encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken =
          request $ basicRequestBuilder encoded encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

    let postResetPasswordRWithToken encoded encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken =
          request $ do
            basicRequestBuilder encoded encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken
            addTokenFromCookie

    let email        = "example@gmail.com" :: Text
        new          = "password"           :: Text
        confirm      = "password"           :: Text
        weakPassword = "pa"                 :: Text
        body         = object [ "new" .= new, "confirm" .= confirm ]
        encoded      = encode body

    it "with malformed json request body gives a 200 and the response body contains \"message\":\"Malformed Credentials JSON\"" $ do

      userEntity <- createUser "example@gmail.com"
      let (Entity _id _) = userEntity

      getCheckR

      let malformedJson = encodeUtf8 "{\"adsfasdf\":\"dfadfas\",}"
          userId = T.pack . show . unSqlBackendKey . unUserKey $ _id

      encryptedAndUrlEncodedUserId <- encryptAndUrlEncode userId
      encryptedAndUrlEncodedVerificationToken <- encryptAndUrlEncode "a"

      postResetPasswordRWithToken malformedJson encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"Malformed Credentials JSON\""

    it "with empty json request body gives a 200 and the response body contains \"message\":\"No email provided\"" $ do

      userEntity <- createUser "example@gmail.com"
      let (Entity _id _) = userEntity

      getCheckR

      let emptyBody = emptyObject
          encodedEmptyBody = encode emptyBody
      
      encryptedAndUrlEncodedUserId <- encryptAndUrlEncode userId
      encryptedAndUrlEncodedVerificationToken <- encryptAndUrlEncode "a"

      postResetPasswordRWithToken encodedEmptyBody encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"No email provided\""


--    it "gives a 200 and the body contains \"message\":\"Password updated\"" $ do
--
--      userEntity <- createUser "steve.papadogiannis1992@gmail.com"
--      let (Entity _id _) = userEntity
--
--      let newPassword = "newPassword" :: Text
--          confirmPassword = "newPassword" :: Text
--          body = object [ "new" .= newPassword, "confirm" .= confirmPassword ]
--          encoded = encode body
--          userId = T.pack . show . unSqlBackendKey . unUserKey $ _id
--
--      encryptedAndUrlEncodedUserId <- encryptAndUrlEncode userId
--      encryptedAndUrlEncodedVerificationToken <- encryptAndUrlEncode "a"
--
--      request $ do
--        setMethod "POST"
--        setUrl $ AuthR $ PluginR "email" ["reset-password", encryptedAndUrlEncodedUserId , encryptedAndUrlEncodedVerificationToken]
--        setRequestBody encoded
--        addRequestHeader ("Content-Type", "application/json")
--
--      statusIs 200
--
----            [Entity _id user] <- runDB $ selectList [UserVerkey ==. Just "a"] []
----            assertEq "Should have " comment (Comment message Nothing)
--      bodyContains "\"message\":\"Password updated\""
