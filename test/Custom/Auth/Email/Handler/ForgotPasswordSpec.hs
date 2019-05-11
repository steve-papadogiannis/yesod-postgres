{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts  #-}

module Custom.Auth.Email.Handler.ForgotPasswordSpec (spec) where

import TestImport

spec :: Spec
spec = withApp $ do

  describe "Post request to http://localhost:3000/auth/plugin/email/forgot-password" $ do

    let getCheckR = do
          get ("http://localhost:3000/auth/check" :: Text)
          statusIs 200

    let basicRequestBuilder encoded = do
          setMethod "POST"
          setUrl $ AuthR $ PluginR "email" ["forgot-password"]
          setRequestBody encoded
          addRequestHeader ("Content-Type", "application/json")

    let postRegisterR encoded =
          request $ basicRequestBuilder encoded

    let postRegisterRWithToken encoded =
          request $ do
            basicRequestBuilder encoded
            addTokenFromCookie

    let email        = "example@gmail.com" :: Text
        body         = object [ "email" .= email ]
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

    it "with invalid email gives a 200 and the body contains \"message\":\"Invalid email address provided\"" $ do

      getCheckR

      let invalidEmail = "examplegmail.com" :: Text
          invalidBody = object [ "email" .= invalidEmail ]
          invalidBodyEncoded = encode invalidBody

      postRegisterRWithToken invalidBodyEncoded

      statusIs 200
      bodyContains "\"message\":\"Invalid email address provided\""

    it "with valid email gives a 200 and the body contains \"message\":\"Forgot Password request was unsuccessful due to an internal error\"" $ do

      getCheckR

      postRegisterRWithToken encoded

      statusIs 200
      bodyContains "\"message\":\"Forgot Password request was unsuccessful due to an internal error\""

    it "with valid email gives a 200 and the body contains \"message\":\"Forgot Password request was unsuccessful due to an internal error\"" $ do

      getCheckR

      let password = "password" :: Text
          additionalFieldBody = object [ "email" .= email, "password" .= password ]
          additionalFieldBodyEncoded = encode additionalFieldBody

      postRegisterRWithToken additionalFieldBodyEncoded

      statusIs 200
      bodyContains "\"message\":\"Forgot Password request was unsuccessful due to an internal error\""

    it "with capital containing email gives a 200 and the body contains \"message\":\"A reset password e-mail has been sent to example@gmail.com.\"" $ do

      getCheckR

      _ <- createUser ("example@gmail.com" :: Text)

      let capitalizedEmail = "EXAMPLE@gmail.com" :: Text
          bodyWithCapitalizedEmail = object [ "email" .= capitalizedEmail ]
          encodedBodyWithCapitalizedEmail = encode bodyWithCapitalizedEmail

      postRegisterRWithToken encodedBodyWithCapitalizedEmail

      statusIs 200
      bodyContains "\"message\":\"A reset password e-mail has been sent to example@gmail.com.\""

    it "with valid email gives a 200 and the body contains \"message\":\"A reset password e-mail has been sent to example@gmail.com.\"" $ do

      getCheckR

      _ <- createUser ("example@gmail.com" :: Text)

      postRegisterRWithToken encoded

      statusIs 200
      bodyContains "\"message\":\"A reset password e-mail has been sent to example@gmail.com.\""

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

  describe "Get request to http://localhost:3000/auth/plugin/email/forgot-password" $

    it "gives a 404 Not Found" $ do

      get ("http://localhost:3000/auth/plugin/email/forgot-password" :: Text)
      statusIs 404