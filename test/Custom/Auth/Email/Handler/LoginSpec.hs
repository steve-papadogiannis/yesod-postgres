{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts  #-}

module Custom.Auth.Email.Handler.LoginSpec (spec) where

import Database.Persist.Sql
import Data.Time.Clock
import TestImport

spec :: Spec
spec = withApp $ do

  describe "Post request to http://localhost:3000/auth/plugin/email/login" $ do

    let getCheckR = do
          TestImport.get ("http://localhost:3000/auth/check" :: Text)
          statusIs 200

    let basicRequestBuilder encoded = do
          setMethod "POST"
          setUrl $ AuthR $ PluginR "email" ["login"]
          setRequestBody encoded
          addRequestHeader ("Content-Type", "application/json")

    let postLoginR encoded =
          request $ basicRequestBuilder encoded

    let postLoginRWithToken encoded =
          request $ do
            basicRequestBuilder encoded
            addTokenFromCookie

    let email        = "example@gmail.com" :: Text
        password     = "password"          :: Text
        body         = object [ "email" .= email, "password" .= password ]
        encoded      = encode body

    it "with malformed json request body gives a 200 and the response body contains \"message\":\"Malformed Credentials JSON\"" $ do

      getCheckR

      let malformedJson = encodeUtf8 "{\"adsfasdf\":\"dfadfas\",}"

      postLoginRWithToken malformedJson

      statusIs 200
      bodyContains "\"message\":\"Malformed Credentials JSON\""

    it "with empty json request body gives a 200 and the response body contains \"message\":\"No email provided\"" $ do

      getCheckR

      let emptyBody = emptyObject
          encodedEmptyBody = encode emptyBody

      postLoginRWithToken encodedEmptyBody

      statusIs 200
      bodyContains "\"message\":\"No email provided\""

    it "with email only json request body gives a 200 and the response body contains \"message\":\"No password provided\"" $ do

      getCheckR

      let onlyEmailBody = object [ "email" .= email ]
          encodedEmailBody = encode onlyEmailBody

      postLoginRWithToken encodedEmailBody

      statusIs 200
      bodyContains "\"message\":\"No password provided\""

    it "with password only json request body gives a 200 and the response body contains \"message\":\"No email provided\"" $ do

      getCheckR

      let onlyPasswordBody = object [ "password" .= password ]
          encodedOnlyPasswordBody = encode onlyPasswordBody

      postLoginRWithToken encodedOnlyPasswordBody

      statusIs 200
      bodyContains "\"message\":\"No email provided\""

    it "with email and wrong password json request body gives a 200 and the response body contains \"message\":\"Invalid email/password combination\"" $ do

      getCheckR

      let wrongPassword             = "wrongPassword" :: Text
          wrongPasswordBody        = object [ "email" .= email, "password" .= wrongPassword ]
          encodedWrongPasswordBody = encode wrongPasswordBody

      userEntity <- createUser email
      let (Entity _id _) = userEntity

      postLoginRWithToken encodedWrongPasswordBody

      statusIs 401
      bodyContains "\"message\":\"Invalid email/password combination\""

    it "with email and password without user in db json request body gives a 200 and the response body contains \"message\":\"Login for user failed\"" $ do

      getCheckR

      postLoginRWithToken encoded

      statusIs 401
      bodyContains "\"message\":\"Login for user failed\""

    it "with invalid email and password without user in db json request body gives a 200 and the response body contains \"message\":\"Invalid email address provided\"" $ do

      getCheckR

      let invalidEmail            = "examplegmail.com" :: Text
          invalidEmailBody        = object [ "email" .= invalidEmail, "password" .= password ]
          encodedInvalidEmailBody = encode invalidEmailBody

      postLoginRWithToken encodedInvalidEmailBody

      statusIs 401
      bodyContains "\"message\":\"Invalid email address provided\""

    it "with email and password with unverified user in db json request body gives a 200 and the response body contains \"message\":\"Account for user example@gmail.com is not verified\"" $ do

      getCheckR

      _ <- runDB $ do
        now <- liftIO getCurrentTime
        insertEntity User
            { userEmail = email
            , userPassword = Just "sha256|16|OvqmNn950c2neU9JR5dbRg==|qwqgII7lLdzyXQT8hCpVoqj7cveU/KnupjImpAa5Ob0="
            , userVerified = False
            , userVerkey = Just ("a" :: Text)
            , userTokenExpiresAt = addUTCTime nominalDay now
            }

      postLoginRWithToken encoded

      statusIs 401
      bodyContains "\"message\":\"Account for user example@gmail.com is not verified\""

    it "with email and password and unset user password json request body gives a 200 and the response body contains \"message\":\"Invalid email/password combination\"" $ do

      getCheckR

      _ <- runDB $ do
        now <- liftIO getCurrentTime
        insertEntity User
            { userEmail = email
            , userPassword = Nothing
            , userVerified = True
            , userVerkey = Just ("a" :: Text)
            , userTokenExpiresAt = addUTCTime nominalDay now
            }

      postLoginRWithToken encoded

      statusIs 401
      bodyContains "\"message\":\"Invalid email/password combination\""

    it "with capitalized email and password json request body gives a 200 and the body contains \"message\":\"Login successful\"" $ do

      getCheckR

      let capitalizedEmail            = "EXAMPLE@gmail.com" :: Text
          capitalizedEmailBody        = object [ "email" .= capitalizedEmail, "password" .= password ]
          encodedCapitalizedEmailBody = encode capitalizedEmailBody

      userEntity <- createUser email
      let (Entity _id _) = userEntity

      postLoginRWithToken encodedCapitalizedEmailBody

      statusIs 200
      bodyContains "\"message\":\"Login Successful\""

    it "gives a 200 and the body contains \"message\":\"Login successful\"" $ do

      getCheckR

      userEntity <- createUser email
      let (Entity _id _) = userEntity

      postLoginRWithToken encoded

      statusIs 200
      bodyContains "\"message\":\"Login Successful\""

    it "gives a 200 and the body contains \"message\":\"Login successful\"" $ do

      postLoginR encoded

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

  describe "Get request to http://localhost:3000/auth/plugin/email/login" $

    it "gives a 404 Not Found" $ do

      TestImport.get ("http://localhost:3000/auth/plugin/email/login" :: Text)
      statusIs 404
