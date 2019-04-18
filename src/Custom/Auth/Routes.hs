{-# LANGUAGE QuasiQuotes, TypeFamilies, TemplateHaskell #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE ViewPatterns #-}
module Custom.Auth.Routes where

import Yesod.Core
import Data.Text (Text)

data Auth = Auth

mkYesodSubData "Auth" [parseRoutes|
/check                            CheckR          GET
/logout                           LogoutR         POST
/plugin/#Text/*Texts              PluginR
|]
