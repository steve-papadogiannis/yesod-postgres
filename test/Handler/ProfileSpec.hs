{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
module Handler.ProfileSpec (spec) where

import TestImport

spec :: Spec
spec = withApp $
    describe "Profile page" $ do
        it "asserts no access to my-account for anonymous users" $ do
            get ProfileR
            statusIs 403

        it "asserts access to my-account for authenticated users" $ do
            userEntity <- createUser "steve.papadogiannis@gmail.com"
            authenticateAs userEntity

            get ProfileR
            statusIs 200

        it "asserts user's information is shown" $ do
            userEntity <- createUser "steve.papadogiannis@gmail.com"
            authenticateAs userEntity

            get ProfileR
            let (Entity _ user) = userEntity
            assertEq "user table empty" "steve.papadogiannis@gmail.com" $ unpack $ userEmail user
