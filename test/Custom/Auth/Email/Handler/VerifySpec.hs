{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts  #-}

module Custom.Auth.Email.Handler.VerifySpec (spec) where

import qualified Data.Text            as T
import           Database.Persist.Sql
import           Data.Time.Clock
import           TestImport

spec :: Spec
spec = withApp $ do

  describe "Get request to http://localhost:3000/auth/plugin/email/verify" $ do

    let getCheckR = do
          TestImport.get ("http://localhost:3000/auth/check" :: Text)
          statusIs 200

    let basicRequestBuilder encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken = do
          setMethod "GET"
          setUrl $ AuthR $ PluginR "email" ["verify", encryptedAndUrlEncodedUserId, encryptedAndUrlEncodedVerificationToken]

    let getEmailVerificationR encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken =
          request $ basicRequestBuilder encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

    let email         = "example@gmail.com" :: Text
        extractId key = T.pack . show . unSqlBackendKey . unUserKey $ key

    let mUserEntity                   = createUser "example@gmail.com"
        mEncryptedAndUrlEncodedUserId = encryptAndUrlEncode . extractId
        mEncryptedAndUrlEncodedVerificationToken = encryptAndUrlEncode "a"

    it "with invalid encryptedUserId gives a 200 and the response body contains \"message\":\"Unable to decrypt asfjklasjdflk\"" $ do

      getCheckR

      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      getEmailVerificationR "asfjklasjdflk" encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"Unable to decrypt asfjklasjdflk\""

    it "with invalid encryptedVerificationToken gives a 200 and the response body contains \"message\":\"Unable to decrypt asfjklasjdflk\"" $ do

      (Entity _id _) <- mUserEntity

      getCheckR

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id

      getEmailVerificationR encryptedAndUrlEncodedUserId "asfjklasjdflk"

      statusIs 200
      bodyContains "\"message\":\"Unable to decrypt asfjklasjdflk\""

    it "with invalid userId gives a 200 and the response body contains \"message\":\"Unable to parse path piece a\"" $ do

      getCheckR

      encryptedAndUrlEncodedUserId <- encryptAndUrlEncode "a"
      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      getEmailVerificationR encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"Unable to parse path piece a\""

    it "with invalid userId gives a 200 and the response body contains \"message\":\"I'm sorry, but that was an invalid verification key.\"" $ do

      getCheckR

      encryptedAndUrlEncodedUserId <- encryptAndUrlEncode "1"
      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      getEmailVerificationR encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"I'm sorry, but that was an invalid verification key.\""

    it "with invalid verification token gives a 200 and the response body contains \"message\":\"I'm sorry, but that was an invalid verification key.\"" $ do

      (Entity _id _) <- mUserEntity

      getCheckR

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id
      encryptedAndUrlEncodedVerificationToken <- encryptAndUrlEncode "b"

      getEmailVerificationR encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"I'm sorry, but that was an invalid verification key.\""

    it "with invalid stored verification token gives a 200 and the response body contains \"message\":\"I'm sorry, but that was an invalid verification key.\"" $ do

      userEntity <- runDB $ do
        now <- liftIO getCurrentTime
        insertEntity User
            { userEmail = email
            , userPassword = Just "sha256|16|FnW1y47QCWc85WzoClsjjA==|m5TunH54L9eFCYJyz5UIeVv50E8Uv5+ld3fL3Amev1E="
            , userVerified = True
            , userVerkey = Nothing
            , userTokenExpiresAt = addUTCTime nominalDay now
            }

      getCheckR

      let (Entity _id _) = userEntity

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id
      encryptedAndUrlEncodedVerificationToken <- encryptAndUrlEncode "b"

      getEmailVerificationR encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"I'm sorry, but that was an invalid verification key.\""

    it "with expired verification token gives a 200 and the response body contains \"message\":\"Your verification link has expired. Please re-register your account\"" $ do

      userEntity <- runDB $ do
        now <- liftIO getCurrentTime
        insertEntity User
            { userEmail = email
            , userPassword = Just "sha256|16|FnW1y47QCWc85WzoClsjjA==|m5TunH54L9eFCYJyz5UIeVv50E8Uv5+ld3fL3Amev1E="
            , userVerified = True
            , userVerkey = Just ("a" :: Text)
            , userTokenExpiresAt = now
            }

      getCheckR

      let (Entity _id _) = userEntity

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id
      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      getEmailVerificationR encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"Your verification link has expired. Please re-register your account\""

    it "with invalid verification token gives a 200 and the response body contains \"message\":\"Address verified\"" $ do

      (Entity _id _) <- mUserEntity

      getCheckR

      encryptedAndUrlEncodedUserId <- mEncryptedAndUrlEncodedUserId _id
      encryptedAndUrlEncodedVerificationToken <- mEncryptedAndUrlEncodedVerificationToken

      getEmailVerificationR encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken

      statusIs 200
      bodyContains "\"message\":\"Address verified\""

  describe "Post request to http://localhost:3000/auth/plugin/email/verify" $

    it "gives a 405 Method not Allowed" $ do

      post ("http://localhost:3000/auth/plugin/email/verify" :: Text)
      statusIs 404