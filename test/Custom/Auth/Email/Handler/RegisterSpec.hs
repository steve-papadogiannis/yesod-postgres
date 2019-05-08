{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}

module Custom.Auth.Email.Handler.RegisterSpec (spec) where

import TestImport

spec :: Spec
spec = withApp $ do
  describe "Post request to http://localhost:3000/auth/plugin/email/register" $
    it "gives a 200 and the body contains \"message\":\"Password must be at least three characters\"" $ do
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

  describe "Get request to http://localhost:3000/auth/plugin/email/register" $
    it "gives a 404 Not Found" $ do
      get ("http://localhost:3000/auth/plugin/email/register" :: Text)
      statusIs 404