{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts  #-}

module Custom.Auth.Email.Handler.RegisterSpec (spec) where

import TestImport

spec :: Spec
spec = withApp $ do
  describe "Post request to http://localhost:3000/auth/plugin/email/register" $ do

    let getCheckR = do
         get ("http://localhost:3000/auth/check" :: Text)
         statusIs 200

    let basicRequestBuilder encoded = do
          setMethod "POST"
          setUrl $ AuthR $ PluginR "email" ["register"]
          setRequestBody encoded
          addRequestHeader ("Content-Type", "application/json")

    let postRegisterR encoded =
          request $ basicRequestBuilder encoded

    let postRegisterRWithToken encoded =
          request $ do
            basicRequestBuilder encoded
            addTokenFromCookie

    let email        = "example@gmail.com" :: Text
        password     = "password"          :: Text
        weakPassword = "pa"                :: Text
        body         = object [ "email" .= email, "password" .= password ]
        encoded      = encode body

    it "with malformed json request body gives a 200 and the response body contains \"message\":\"Malformed Credentials JSON\"" $ do

      getCheckR

      let malformedJson = encodeUtf8 "{\"adsfasdf\":\"dfadfas\",}"

      postRegisterRWithToken malformedJson

      statusIs 200
      bodyContains "\"message\":\"Malformed Credentials JSON\""

    it "with empty json request body gives a 200 and the response body contains \"message\":\"No email provided\"" $ do

      getCheckR

      let emptyBody = emptyObject
          encodedEmptyBody = encode emptyBody

      postRegisterRWithToken encodedEmptyBody

      statusIs 200
      bodyContains "\"message\":\"No email provided\""

    it "with only email in request body gives a 200 and the response body contains \"message\":\"No password provided\"" $ do

      getCheckR

      let onlyEmail = object [ "email" .= email ]
          onlyEmailEncoded = encode onlyEmail

      postRegisterRWithToken onlyEmailEncoded

      statusIs 200
      bodyContains "\"message\":\"No password provided\""

    it "with only email in request body gives a 200 and the response body contains \"message\":\"No email provided\"" $ do

      getCheckR

      let onlyPassword = object [ "password" .= weakPassword ]
          onlyPasswordEncoded = encode onlyPassword

      postRegisterRWithToken onlyPasswordEncoded

      statusIs 200
      bodyContains "\"message\":\"No email provided\""

    it "with password \"pa\" gives a 200 and the body contains \"message\":\"Password must be at least three characters\"" $ do

      getCheckR

      let weakBody = object [ "email" .= email, "password" .= weakPassword ]
          weakBodyEncoded = encode weakBody

      postRegisterRWithToken weakBodyEncoded

      statusIs 200
      bodyContains "\"message\":\"Password must be at least three characters\""

    it "with invalid email and password gives a 200 and the body contains \"message\":\"Invalid email address provided\"" $ do

      getCheckR

      let invalidEmail = "examplegmail.com" :: Text
          invalidBody = object [ "email" .= invalidEmail, "password" .= weakPassword ]
          invalidBodyEncoded = encode invalidBody

      postRegisterRWithToken invalidBodyEncoded

      statusIs 200
      bodyContains "\"message\":\"Invalid email address provided\""

    it "with valid email and password gives a 200 and the body contains \"message\":\"A confirmation e-mail has been sent to example@gmail.com.\"" $ do

      getCheckR

      postRegisterRWithToken encoded

      statusIs 200
      bodyContains "\"message\":\"A confirmation e-mail has been sent to example@gmail.com.\""

    it "with capital containing email and password gives a 200 and the body contains \"message\":\"A confirmation e-mail has been sent to example@gmail.com.\"" $ do

      getCheckR

      let capitalizedEmail = "EXAMPLE@gmail.com" :: Text
          bodyWithCapitalizedEmail = object [ "email" .= capitalizedEmail, "password" .= password ]
          encodedBodyWithCapitalizedEmail = encode bodyWithCapitalizedEmail

      postRegisterRWithToken encodedBodyWithCapitalizedEmail

      statusIs 200
      bodyContains "\"message\":\"A confirmation e-mail has been sent to example@gmail.com.\""

    it "with valid email and password and already registerd user with this email gives a 200 and the body contains \"message\":\"This email is already registered\"" $ do

      getCheckR

      _ <- createUser ("example@gmail.com" :: Text)

      postRegisterRWithToken encoded

      statusIs 200
      bodyContains "\"message\":\"This email is already registered\""

    it "with valid email and password gives a 403 and the body contains csrf text" $ do

      postRegisterR encoded

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

    it "with valid email and password and invalid user in db gives a 200 and the body contains \"message\":\"User row example@gmail.com not in valid state\"" $ do

      getCheckR

      runDB $ do
        now <- liftIO getCurrentTime
        _ <- insertEntity User
            { userEmail = email
            , userPassword = Just "sha256|16|FnW1y47QCWc85WzoClsjjA==|m5TunH54L9eFCYJyz5UIeVv50E8Uv5+ld3fL3Amev1E="
            , userVerified = True
            , userVerkey = Nothing
            , userTokenExpiresAt = addUTCTime nominalDay now
            }

      postRegisterRWithToken encoded

      statusIs 200
      bodyContains "\"message\":\"User row example@gmail.com not in valid state\""

  describe "Get request to http://localhost:3000/auth/plugin/email/register" $

    it "gives a 404 Not Found" $ do

      get ("http://localhost:3000/auth/plugin/email/register" :: Text)
      statusIs 404
