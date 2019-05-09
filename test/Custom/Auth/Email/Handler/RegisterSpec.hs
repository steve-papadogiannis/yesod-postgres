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

    let postRegisterR encoded =
          request $ do
            setMethod "POST"
            setUrl $ AuthR $ PluginR "email" ["register"]
            setRequestBody encoded
            addRequestHeader ("Content-Type", "application/json")
            addTokenFromCookie

    it "with malformed json request body gives a 200 and the response body contains \"message\":\"Malformed Credentials JSON\"" $ do

      getCheckR

      let body = encodeUtf8 "{\"adsfasdf\":\"dfadfas\",}"

      postRegisterR body

      statusIs 200
      bodyContains "\"message\":\"Malformed Credentials JSON\""

    it "with empty json request body gives a 200 and the response body contains \"message\":\"No email provided\"" $ do

      getCheckR

      let body = emptyObject
          encoded = encode body

      postRegisterR encoded

      statusIs 200
      bodyContains "\"message\":\"No email provided\""

    it "with only email in request body gives a 200 and the response body contains \"message\":\"No password provided\"" $ do

      getCheckR

      let email = "example@gmail.com" :: Text
          body = object [ "email" .= email ]
          encoded = encode body

      postRegisterR encoded

      statusIs 200
      bodyContains "\"message\":\"No password provided\""

    it "with only email in request body gives a 200 and the response body contains \"message\":\"No email provided\"" $ do

      getCheckR

      let password = "pa" :: Text
          body = object [ "password" .= password ]
          encoded = encode body

      postRegisterR encoded

      statusIs 200
      bodyContains "\"message\":\"No email provided\""

    it "with password \"pa\" gives a 200 and the body contains \"message\":\"Password must be at least three characters\"" $ do

      getCheckR

      let email = "example@gmail.com" :: Text
          password = "pa" :: Text
          body = object [ "email" .= email, "password" .= password ]
          encoded = encode body

      postRegisterR encoded

      statusIs 200
      bodyContains "\"message\":\"Password must be at least three characters\""

    it "with invalid email and password gives a 200 and the body contains \"message\":\"Invalid email address provided\"" $ do

      getCheckR

      let email = "examplegmail.com" :: Text
          password = "password" :: Text
          body = object [ "email" .= email, "password" .= password ]
          encoded = encode body

      postRegisterR encoded

      statusIs 200
      bodyContains "\"message\":\"Invalid email address provided\""

    it "with valid email and password gives a 200 and the body contains \"message\":\"A confirmation e-mail has been sent to example@gmail.com.\"" $ do

      getCheckR

      let email = "example@gmail.com" :: Text
          password = "password" :: Text
          body = object [ "email" .= email, "password" .= password ]
          encoded = encode body

      postRegisterR encoded

      statusIs 200
      bodyContains "\"message\":\"A confirmation e-mail has been sent to example@gmail.com.\""

    it "with capital containing email and password gives a 200 and the body contains \"message\":\"A confirmation e-mail has been sent to example@gmail.com.\"" $ do

      getCheckR

      let email = "EXAMPLE@gmail.com" :: Text
          password = "password" :: Text
          body = object [ "email" .= email, "password" .= password ]
          encoded = encode body

      postRegisterR encoded

      statusIs 200
      bodyContains "\"message\":\"A confirmation e-mail has been sent to example@gmail.com.\""

    it "with valid email and password and already registerd user with this email gives a 200 and the body contains \"message\":\"This email is already registered\"" $ do

      getCheckR

      let email = "example@gmail.com" :: Text
          password = "password" :: Text
          body = object [ "email" .= email, "password" .= password ]
          encoded = encode body

      _ <- createUser ("example@gmail.com" :: Text)

      postRegisterR encoded

      statusIs 200
      bodyContains "\"message\":\"This email is already registered\""

    it "with valid email and password gives a 403 and the body contains csrf text" $ do

      let email = "example@gmail.com" :: Text
          password = "password" :: Text
          body = object [ "email" .= email, "password" .= password ]
          encoded = encode body

      request $ do
        setMethod "POST"
        setUrl $ AuthR $ PluginR "email" ["register"]
        setRequestBody encoded
        addRequestHeader ("Content-Type", "application/json")

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
    
  describe "Get request to http://localhost:3000/auth/plugin/email/register" $

    it "gives a 404 Not Found" $ do

      get ("http://localhost:3000/auth/plugin/email/register" :: Text)
      statusIs 404
