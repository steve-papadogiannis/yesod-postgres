{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}

module Custom.Auth.Email.Handler.LoginSpec (spec) where

import TestImport

spec :: Spec
spec = withApp $

  describe "Post request to http://localhost:3000/auth/plugin/email/login" $

    let getCheckR = do
          get ("http://localhost:3000/auth/check" :: Text)
          statusIs 200

    let basicRequestBuilder encoded = do
          setMethod "POST"
          setUrl $ AuthR $ PluginR "email" ["login"]
          setRequestBody encoded
          addRequestHeader ("Content-Type", "application/json")

    let postForgotPasswordR encoded =
          request $ basicRequestBuilder encoded

    let postForgotPasswordRWithToken encoded =
          request $ do
            basicRequestBuilder encoded
            addTokenFromCookie

    let email        = "example@gmail.com" :: Text
        password     = "password"
        body         = object [ "email" .= email, "password" .= password ]
        encoded      = encode body

    it "gives a 200 and the body contains \"message\":\"Login successful\"" $ do

      let email = "steve.papadogiannis1992@gmail.com" :: Text
          password = "kurwa" :: Text
          body = object [ "email" .= email, "password" .= password ]
          encoded = encode body

      userEntity <- createUser email
      let (Entity _id _) = userEntity

      request $ do
        setMethod "POST"
        setUrl $ AuthR $ PluginR "email" ["login"]
        setRequestBody encoded
        addRequestHeader ("Content-Type", "application/json")

      statusIs 200

--            [Entity _id user] <- runDB $ selectList [UserVerkey ==. Just "a"] []
--            assertEq "Should have " comment (Comment message Nothing)
      bodyContains "\"message\":\"Login Successful\""
