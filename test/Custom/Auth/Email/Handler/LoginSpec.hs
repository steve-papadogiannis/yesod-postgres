{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}

module Custom.Auth.Email.Handler.LoginSpec (spec) where

import TestImport
import Data.Aeson
import           Database.Persist.Sql
import qualified Data.Text                  as T

spec :: Spec
spec = withApp $ do
    describe "Post request to http://localhost:3000/auth/plugin/email/login" $
        it "gives a 200 and the body contains \"message\":\"Login successful\"" $ do

          let email = "steve.papadogiannis1992@gmail.com" :: Text
              password = "kurwa" :: Text
              body = object [ "email" .= email, "password" .= password ]
              encoded = encode body

          userEntity <- createUser email
          let (Entity _id user) = userEntity

          request $ do
            setMethod "POST"
            setUrl $ AuthR $ PluginR "email" ["login"]
            setRequestBody encoded
            addRequestHeader ("Content-Type", "application/json")

          statusIs 200

--            [Entity _id user] <- runDB $ selectList [UserVerkey ==. Just "a"] []
--            assertEq "Should have " comment (Comment message Nothing)
          bodyContains "\"message\":\"Login Successful\""