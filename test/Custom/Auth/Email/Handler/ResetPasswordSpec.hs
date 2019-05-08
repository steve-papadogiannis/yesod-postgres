{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}

module Custom.Auth.Email.Handler.ResetPasswordSpec (spec) where

import TestImport
import Data.Aeson
import           Database.Persist.Sql
import qualified Data.Text                  as T

spec :: Spec
spec = withApp $ do
    describe "Post request to ResetPasswordR" $
        it "gives a 200 and the body contains \"message\":\"Password updated\"" $ do

          userEntity <- createUser "steve.papadogiannis1992@gmail.com"
          let (Entity _id user) = userEntity

          let newPassword = "newPassword" :: Text
              confirmPassword = "newPassword" :: Text
              body = object [ "new" .= newPassword, "confirm" .= confirmPassword ]
              encoded = encode body
              id = T.pack . show . unSqlBackendKey . unUserKey $ _id

          encryptedAndUrlEncodedUserId <- encryptAndUrlEncode id
          encryptedAndUrlEncodedVerificationToken <- encryptAndUrlEncode "a"

          request $ do
            setMethod "POST"
            setUrl $ AuthR $ PluginR "email" ["reset-password", encryptedAndUrlEncodedUserId , encryptedAndUrlEncodedVerificationToken]
            setRequestBody encoded
            addRequestHeader ("Content-Type", "application/json")

          statusIs 200

--            [Entity _id user] <- runDB $ selectList [UserVerkey ==. Just "a"] []
--            assertEq "Should have " comment (Comment message Nothing)
          bodyContains "\"message\":\"Password updated\""