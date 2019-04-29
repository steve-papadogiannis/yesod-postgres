{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}

module Custom.Auth.EmailSpec (spec) where

import TestImport
import Data.Aeson

spec :: Spec
spec = withApp $ do
    describe "valid request" $ do
      it "gives a 200" $ do
          get ("http://localhost:3000/auth/check" :: Text)
          statusIs 200