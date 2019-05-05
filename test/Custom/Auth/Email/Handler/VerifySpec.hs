{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}

module Custom.Auth.Email.Handler.VerifySpec (spec) where

import TestImport

spec :: Spec
spec = withApp $ do
  describe "Get request to CheckR without authenticated user" $
    it "gives a 200 and the body contains \"logged_in\":false" $ do
      get ("http://localhost:3000/auth/check" :: Text)
      statusIs 200

      bodyContains "\"logged_in\":false"
  describe "Get request to CheckR with authenticated user" $
    it "gives a 200 and the body contains \"logged_in\":true" $ do

      userEntity <- createUser "steve.papadogiannis@gmail.com"
      authenticateAs userEntity

      get ("http://localhost:3000/auth/check" :: Text)
      statusIs 200

      bodyContains "\"logged_in\":true"

      assertHeaderWithoutValue "Set-Cookie"

  describe "Post request to CheckR" $
    it "gives a 405 Method not Allowed" $ do
      post ("http://localhost:3000/auth/check" :: Text)
      statusIs 405