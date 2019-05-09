{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}

module Custom.Auth.Email.Handler.RegisterSpec (spec) where

import TestImport

spec :: Spec
spec = withApp $ do
  describe "Post request to http://localhost:3000/auth/plugin/email/register" $ do
    it "with only email in request body gives a 200 and the response body contains \"message\":\"No password provided\"" $ do
      get ("http://localhost:3000/auth/check" :: Text)
      statusIs 200

      let email = "example@gmail.com" :: Text
          body = object [ "email" .= email ]
          encoded = encode body

      request $ do
        setMethod "POST"
        setUrl $ AuthR $ PluginR "email" ["register"]
        setRequestBody encoded
        addRequestHeader ("Content-Type", "application/json")
        addTokenFromCookie

      statusIs 200
      bodyContains "\"message\":\"No password provided\""
    it "with only email in request body gives a 200 and the response body contains \"message\":\"No email provided\"" $ do
      get ("http://localhost:3000/auth/check" :: Text)
      statusIs 200

      let password = "pa" :: Text
          body = object [ "password" .= password ]
          encoded = encode body

      request $ do
        setMethod "POST"
        setUrl $ AuthR $ PluginR "email" ["register"]
        setRequestBody encoded
        addRequestHeader ("Content-Type", "application/json")
        addTokenFromCookie

      statusIs 200
      bodyContains "\"message\":\"No email provided\""
    it "with password \"pa\" gives a 200 and the body contains \"message\":\"Password must be at least three characters\"" $ do
      get ("http://localhost:3000/auth/check" :: Text)
      statusIs 200

      let email = "example@gmail.com" :: Text
          password = "pa" :: Text
          body = object [ "email" .= email, "password" .= password ]
          encoded = encode body

      request $ do
        setMethod "POST"
        setUrl $ AuthR $ PluginR "email" ["register"]
        setRequestBody encoded
        addRequestHeader ("Content-Type", "application/json")
        addTokenFromCookie

      statusIs 200
      bodyContains "\"message\":\"Password must be at least three characters\""
    it "with invalid email and password gives a 200 and the body contains \"message\":\"Invalid email address provided\"" $ do
      get ("http://localhost:3000/auth/check" :: Text)
      statusIs 200

      let email = "examplegmail.com" :: Text
          password = "password" :: Text
          body = object [ "email" .= email, "password" .= password ]
          encoded = encode body

      request $ do
        setMethod "POST"
        setUrl $ AuthR $ PluginR "email" ["register"]
        setRequestBody encoded
        addRequestHeader ("Content-Type", "application/json")
        addTokenFromCookie

      statusIs 200
      bodyContains "\"message\":\"Invalid email address provided\""
    it "with valid email and password gives a 200 and the body contains \"message\":\"A confirmation e-mail has been sent to example@gmail.com.\"" $ do
      get ("http://localhost:3000/auth/check" :: Text)
      statusIs 200

      let email = "example@gmail.com" :: Text
          password = "password" :: Text
          body = object [ "email" .= email, "password" .= password ]
          encoded = encode body

      request $ do
        setMethod "POST"
        setUrl $ AuthR $ PluginR "email" ["register"]
        setRequestBody encoded
        addRequestHeader ("Content-Type", "application/json")
        addTokenFromCookie

      statusIs 200
      bodyContains "\"message\":\"A confirmation e-mail has been sent to example@gmail.com.\""
    it "with capital containing email and password gives a 200 and the body contains \"message\":\"A confirmation e-mail has been sent to example@gmail.com.\"" $ do
      get ("http://localhost:3000/auth/check" :: Text)
      statusIs 200

      let email = "EXAMPLE@gmail.com" :: Text
          password = "password" :: Text
          body = object [ "email" .= email, "password" .= password ]
          encoded = encode body

      request $ do
        setMethod "POST"
        setUrl $ AuthR $ PluginR "email" ["register"]
        setRequestBody encoded
        addRequestHeader ("Content-Type", "application/json")
        addTokenFromCookie

      statusIs 200
      bodyContains "\"message\":\"A confirmation e-mail has been sent to example@gmail.com.\""
    
  describe "Get request to http://localhost:3000/auth/plugin/email/register" $
    it "gives a 404 Not Found" $ do
      get ("http://localhost:3000/auth/plugin/email/register" :: Text)
      statusIs 404
