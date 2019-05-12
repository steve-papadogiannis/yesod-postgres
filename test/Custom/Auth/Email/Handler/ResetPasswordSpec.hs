{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts  #-}

module Custom.Auth.Email.Handler.ResetPasswordSpec (spec) where

import qualified Data.Text            as T
import           Database.Persist.Sql
import           Data.Time.Clock
import           TestImport

spec :: Spec
spec = withApp $ do

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

    let email         = "example@gmail.com" :: Text
        new           = "password"           :: Text
        confirm       = "password"           :: Text
        weakPassword  = "pa"                 :: Text
        body          = object [ "new" .= new, "confirm" .= confirm ]
        encoded       = encode body
        extractId key = T.pack . show . unSqlBackendKey . unUserKey $ key

    let mUserEntity                   = createUser "example@gmail.com"
        mEncryptedAndUrlEncodedUserId = encryptAndUrlEncode . extractId
        mEncryptedAndUrlEncodedVerificationToken = encryptAndUrlEncode "a"

    it "with malformed json request body gives a 200 and the response body contains \"message\":\"Malformed Credentials JSON\"" $ do

      (Entity _id _) <- mUserEntity

      getCheckR

      let malformedJson = encodeUtf8 "{\"adsfasdf\":\"dfadfas\",}"

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id
      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      postResetPasswordRWithToken malformedJson encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"Malformed Credentials JSON\""

    it "with empty json request body gives a 200 and the response body contains \"message\":\"No newPassword provided\"" $ do

      (Entity _id _) <- mUserEntity

      getCheckR

      let emptyBody = emptyObject
          encodedEmptyBody = encode emptyBody

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id
      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      postResetPasswordRWithToken encodedEmptyBody encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"No newPassword provided\""

    it "with newPassword json request body gives a 200 and the response body contains \"message\":\"No confirmPassword provided\"" $ do

      (Entity _id _) <- mUserEntity

      getCheckR

      let bodyWithoutConfirmPassword = object [ "new" .= new ]
          encodedBodyWithoutConfirmPassword = encode bodyWithoutConfirmPassword

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id
      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      postResetPasswordRWithToken encodedBodyWithoutConfirmPassword encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"No confirmPassword provided\""

    it "with confirmPassword json request body gives a 200 and the response body contains \"message\":\"No newPassword provided\"" $ do

      (Entity _id _) <- mUserEntity

      getCheckR

      let bodyWithoutNewPassword = object [ "confirm" .= confirm ]
          encodedBodyWithoutNewPassword = encode bodyWithoutNewPassword

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id
      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      postResetPasswordRWithToken encodedBodyWithoutNewPassword encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"No newPassword provided\""

    it "with invalid encryptedUserId gives a 200 and the response body contains \"message\":\"Unable to decrypt asfjklasjdflk\"" $ do

      getCheckR

      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      postResetPasswordRWithToken encoded "asfjklasjdflk" encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"Unable to decrypt asfjklasjdflk\""

    it "with invalid encryptedVerificationToken gives a 200 and the response body contains \"message\":\"Unable to decrypt asfjklasjdflk\"" $ do

      (Entity _id _) <- mUserEntity

      getCheckR

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id

      postResetPasswordRWithToken encoded encryptedAndUrlEncodedUserId "asfjklasjdflk"

      statusIs 200
      bodyContains "\"message\":\"Unable to decrypt asfjklasjdflk\""

    it "with invalid userId gives a 200 and the response body contains \"message\":\"Unable to parse path piece a\"" $ do

      getCheckR

      encryptedAndUrlEncodedUserId <- encryptAndUrlEncode "a"
      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      postResetPasswordRWithToken encoded encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"Unable to parse path piece a\""

    it "with invalid userId gives a 200 and the response body contains \"message\":\"Invalid verification key\"" $ do

      getCheckR

      encryptedAndUrlEncodedUserId <- encryptAndUrlEncode "1"
      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      postResetPasswordRWithToken encoded encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"Invalid verification key\""

    it "with different new and confirm password json request body gives a 200 and the response body contains \"message\":\"Passwords did not match, please try again\"" $ do

      (Entity _id _) <- mUserEntity

      getCheckR

      let bodyWithDifferentPasswords = object [ "new" .= new, "confirm" .= ("password1" :: Text) ]
          encodedBodyWithDifferentPasswords = encode bodyWithDifferentPasswords

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id
      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      postResetPasswordRWithToken encodedBodyWithDifferentPasswords encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"Passwords did not match, please try again\""

    it "with weak new and confirm password json request body gives a 200 and the response body contains \"message\":\"Password must be at least three characters\"" $ do

      (Entity _id _) <- mUserEntity

      getCheckR

      let bodyWithWeakPasswords = object [ "new" .= weakPassword, "confirm" .= weakPassword ]
          encodedBodyWithWeakPasswords = encode bodyWithWeakPasswords

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id
      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      postResetPasswordRWithToken encodedBodyWithWeakPasswords encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"Password must be at least three characters\""

    it "with invalid verification token gives a 200 and the response body contains \"message\":\"Invalid verification key\"" $ do

      (Entity _id _) <- mUserEntity

      getCheckR

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id
      encryptedAndUrlEncodedVerificationToken <- encryptAndUrlEncode "b"

      postResetPasswordRWithToken encoded encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"Invalid verification key\""

    it "with invalid stored verification token gives a 200 and the response body contains \"message\":\"Invalid verification key\"" $ do

      userEntity <- runDB $ do
        now <- liftIO getCurrentTime
        insertEntity User
            { userEmail = email
            , userPassword = Just "sha256|16|FnW1y47QCWc85WzoClsjjA==|m5TunH54L9eFCYJyz5UIeVv50E8Uv5+ld3fL3Amev1E="
            , userVerified = True
            , userVerkey = Nothing
            , userTokenExpiresAt = addUTCTime nominalDay now
            }

      getCheckR

      let (Entity _id _) = userEntity

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id
      encryptedAndUrlEncodedVerificationToken <- encryptAndUrlEncode "b"

      postResetPasswordRWithToken encoded encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"Invalid verification key\""

    it "with expired verification token gives a 200 and the response body contains \"message\":\"Your reset password link has expired\"" $ do

      userEntity <- runDB $ do
        now <- liftIO getCurrentTime
        insertEntity User
            { userEmail = email
            , userPassword = Just "sha256|16|FnW1y47QCWc85WzoClsjjA==|m5TunH54L9eFCYJyz5UIeVv50E8Uv5+ld3fL3Amev1E="
            , userVerified = True
            , userVerkey = Just ("a" :: Text)
            , userTokenExpiresAt = now
            }

      getCheckR

      let (Entity _id _) = userEntity

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id
      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      postResetPasswordRWithToken encoded encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"Your reset password link has expired\""

    it "with valid json request body gives a 200 and the response body contains \"message\":\"Password updated\"" $ do

      (Entity _id _) <- mUserEntity

      getCheckR

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id
      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      postResetPasswordRWithToken encoded encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"Password updated\""

    it "with valid json request body gives a 403 and the body contains csrf text" $ do

      postResetPasswordR encoded "a" "b"

      statusIs 403
      bodyContains $ "<!DOCTYPE html>\n" ++
                     "<html><head><title>Permission Denied</title></head><body><h1>Permission Denied</h1>\n" ++
                     "<p>A valid CSRF token wasn&#39;t present. Because the request could have been forged, it&#39;s been rejected altogether.\n" ++
                     "If you&#39;re a developer of this site, these tips will help you debug the issue:\n" ++
                     "- Read the Yesod.Core.Handler docs of the yesod-core package for details on CSRF protection.\n" ++
                     "- Check that your HTTP client is persisting cookies between requests, like a browser does.\n" ++
                     "- By default, the CSRF token is sent to the client in a cookie named XSRF-TOKEN.\n" ++
                     "- The server is looking for the token in the following locations:\n" ++
                     "  - An HTTP header named X-XSRF-TOKEN (which is not currently set)\n" ++
                     "  - A POST parameter named _token (which is not currently set)</p>\n" ++
                     "</body></html>"

  describe "Get request to http://localhost:3000/auth/plugin/email/reset-password" $

    it "gives a 404 Not Found" $ do

      TestImport.get ("http://localhost:3000/auth/plugin/email/reset-password" :: Text)
      statusIs 404
