{-# LANGUAGE CPP #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE QuasiQuotes, TypeFamilies, TemplateHaskell #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Custom.Auth
    ( -- * Subsite
      Auth
    , AuthRoute
    , Route (..)
    , AuthPlugin (..)
    , getAuth
    , YesodAuth (..)
    , YesodAuthPersist (..)
      -- * Plugin interface
    , Creds (..)
    , setCreds
    , setCredsRedirect
    , clearCreds
    , loginErrorMessage
    , loginErrorMessageI
      -- * User functions
    , AuthenticationResult (..)
    , defaultMaybeAuthId
    , maybeAuthPair
    , maybeAuth
    , requireAuthId
    , requireAuthPair
    , requireAuth
      -- * Exception
    , AuthException (..)
      -- * Helper
    , MonadAuthHandler
    , AuthHandler
      -- * Internal
    , credsKey
    , provideJsonMessage
    , messageJson401
    , asHtml
    ) where

import           Control.Monad.Trans.Maybe
import           UnliftIO                  (withRunInIO, MonadUnliftIO)
import           Custom.Auth.Routes
import           Data.Aeson                 hiding (json)
import           Data.Text                  (Text)
import qualified Data.Text                  as T
import qualified Data.HashMap.Lazy          as Map
import           Network.HTTP.Client        (Manager, Request, withResponse, Response, BodyReader)
import           Network.HTTP.Client.TLS    (getGlobalManager)
import           Yesod.Core
import           Yesod.Persist
import           Custom.Auth.Message        (AuthMessage, defaultMessage)
import qualified Custom.Auth.Message        as Msg
import           Yesod.Form                 (FormMessage)
import           Data.Typeable              (Typeable)
import           Control.Exception          (Exception)
import           Network.HTTP.Types         (Status, internalServerError500, unauthorized401, ok200)
import           Control.Monad              (void)
import qualified Network.Wai                as W
import           Data.Text.Encoding         (decodeUtf8With)
import           Data.Text.Encoding.Error   (lenientDecode)

type AuthRoute = Route Auth
type MonadAuthHandler master m = (MonadHandler m, YesodAuth master, master ~ HandlerSite m, Auth ~ SubHandlerSite m, MonadUnliftIO m)
type AuthHandler master a = forall m. MonadAuthHandler master m => m a
type Method = Text
type Piece = Text

-- | The result of an authentication based on credentials
data AuthenticationResult master
    = Authenticated (AuthId master) -- ^ Authenticated successfully
    | UserError AuthMessage         -- ^ Invalid credentials provided by user
    | ServerError Text              -- ^ Some other error

data AuthPlugin master = AuthPlugin
    { apName :: Text
    , apDispatch :: Method -> [Piece] -> AuthHandler master Value
    }

getAuth :: a -> Auth
getAuth = const Auth

-- | User credentials
data Creds master = Creds
    { credsPlugin :: Text -- ^ How the user was authenticated
    , credsIdent :: Text -- ^ Identifier. Exact meaning depends on plugin.
    , credsExtra :: [(Text, Text)]
    } deriving (Show)

class (Yesod master, PathPiece (AuthId master), RenderMessage master FormMessage) => YesodAuth master where
    type AuthId master

    -- | Perform authentication based on the given credentials.
    --
    -- Default implementation is in terms of @'getAuthId'@
    --
    -- @since: 1.4.4
    authenticate :: (MonadHandler m, HandlerSite m ~ master) => Creds master -> m (AuthenticationResult master)
    authenticate creds = do
        muid <- getAuthId creds

        return $ maybe (UserError Msg.InvalidLogin) Authenticated muid

    -- | Determine the ID associated with the set of credentials.
    --
    -- Default implementation is in terms of @'authenticate'@
    --
    getAuthId :: (MonadHandler m, HandlerSite m ~ master) => Creds master -> m (Maybe (AuthId master))
    getAuthId creds = do
        auth <- authenticate creds

        return $ case auth of
            Authenticated auid -> Just auid
            _ -> Nothing

    -- | Which authentication backends to use.
    authPlugins :: master -> [AuthPlugin master]

    -- | Used for i18n of messages provided by this package.
    renderAuthMessage :: master
                      -> [Text] -- ^ languages
                      -> AuthMessage
                      -> Text
    renderAuthMessage _ _ = defaultMessage

    -- | Return an HTTP connection manager that is stored in the foundation
    -- type. This allows backends to reuse persistent connections. If none of
    -- the backends you're using use HTTP connections, you can safely return
    -- @error \"authHttpManager\"@ here.
    authHttpManager :: (MonadHandler m, HandlerSite m ~ master) => m Manager
    authHttpManager = liftIO getGlobalManager

    -- | Retrieves user credentials, if user is authenticated.
    --
    -- By default, this calls 'defaultMaybeAuthId' to get the user ID from the
    -- session. This can be overridden to allow authentication via other means,
    -- such as checking for a special token in a request header. This is
    -- especially useful for creating an API to be accessed via some means
    -- other than a browser.
    --
    -- @since 1.2.0
    maybeAuthId :: (MonadHandler m, master ~ HandlerSite m) => m (Maybe (AuthId master))

    default maybeAuthId
        :: (MonadHandler m, master ~ HandlerSite m, YesodAuthPersist master, Typeable (AuthEntity master))
        => m (Maybe (AuthId master))
    maybeAuthId = defaultMaybeAuthId

    -- | runHttpRequest gives you a chance to handle an HttpException and retry
    --  The default behavior is to simply execute the request which will throw an exception on failure
    --
    --  The HTTP 'Request' is given in case it is useful to change behavior based on inspecting the request.
    --  This is an experimental API that is not broadly used throughout the yesod-auth code base
    runHttpRequest
      :: (MonadHandler m, HandlerSite m ~ master, MonadUnliftIO m)
      => Request
      -> (Response BodyReader -> m a)
      -> m a
    runHttpRequest req inner = do
      man <- authHttpManager
      withRunInIO $ \run -> withResponse req man $ run . inner

    {-# MINIMAL  (authenticate | getAuthId), authPlugins #-}

{-# DEPRECATED getAuthId "Define 'authenticate' instead; 'getAuthId' will be removed in the next major version" #-}

-- | Internal session key used to hold the authentication information.
--
-- @since 1.2.3
credsKey :: Text
credsKey = "_ID"

-- | Retrieves user credentials from the session, if user is authenticated.
--
-- This function does /not/ confirm that the credentials are valid, see
-- 'maybeAuthIdRaw' for more information. The first call in a request
-- does a database request to make sure that the account is still in the database.
--
-- @since 1.1.2
defaultMaybeAuthId
    :: (MonadHandler m, HandlerSite m ~ master, YesodAuthPersist master, Typeable (AuthEntity master))
    => m (Maybe (AuthId master))
defaultMaybeAuthId = runMaybeT $ do
    s   <- MaybeT $ lookupSession credsKey
    aid <- MaybeT $ return $ fromPathPiece s
    _   <- MaybeT $ cachedAuth aid
    return aid

cachedAuth
    :: ( MonadHandler m
       , YesodAuthPersist master
       , Typeable (AuthEntity master)
       , HandlerSite m ~ master
       )
    => AuthId master
    -> m (Maybe (AuthEntity master))
cachedAuth
    = fmap unCachedMaybeAuth
    . cached
    . fmap CachedMaybeAuth
    . getAuthEntity


loginErrorMessageI
  :: AuthMessage
  -> AuthHandler master Value
loginErrorMessageI = loginErrorMessageMasterI

loginErrorMessageMasterI
  :: (MonadHandler m, HandlerSite m ~ master, YesodAuth master)
  => AuthMessage
  -> m Value
loginErrorMessageMasterI msg = do
  mr <- getMessageRender
  loginErrorMessage (mr msg)

-- | For JSON, send the message and a 401 status
loginErrorMessage
         :: (MonadHandler m, YesodAuth (HandlerSite m))
         => Text
         -> m Value
loginErrorMessage = messageJson401

messageJson401
  :: MonadHandler m
  => Text
  -> m Value
messageJson401 = messageJsonStatus unauthorized401

messageJson500 :: MonadHandler m => Text -> m Value
messageJson500 = messageJsonStatus internalServerError500

messageJson200 :: MonadHandler m => Text -> m Value
messageJson200 = messageJsonStatus ok200

messageJsonStatus
  :: MonadHandler m
  => Status
  -> Text
  -> m Value
messageJsonStatus status msg = do
        let obj = object ["message" .= msg]
        void $ sendResponseStatus status obj
        return obj

provideJsonMessage :: MonadHandler m => Text -> m Value
provideJsonMessage msg = return $ object ["message" .= msg]


setCredsRedirect
  :: (MonadHandler m, YesodAuth (HandlerSite m))
  => Creds (HandlerSite m) -- ^ new credentials
  -> m Value
setCredsRedirect creds = do
    y    <- getYesod
    auth <- authenticate creds
    case auth of
        Authenticated aid -> do
            setSession credsKey $ toPathPiece aid
            messageJson200 "Login Successful"
--            sendResponse res

        UserError msg ->
            case authRoute y of
                Nothing -> do
                    msg' <- renderMessage' msg
                    messageJson401 msg'
                Just _ -> loginErrorMessageMasterI msg

        ServerError msg -> do
            $(logError) msg

            case authRoute y of
                Nothing -> do
                    msg' <- renderMessage' Msg.AuthError
                    messageJson500 msg'
                Just _ -> loginErrorMessageMasterI Msg.AuthError

  where
    renderMessage' msg = do
        langs <- languages
        master <- getYesod
        return $ renderAuthMessage master langs msg

-- | Sets user credentials for the session after checking them with authentication backends.
setCreds :: (MonadHandler m, YesodAuth (HandlerSite m))
         => Bool                  -- ^ if HTTP redirects should be done
         -> Creds (HandlerSite m) -- ^ new credentials
         -> m ()
setCreds doRedirects creds =
    if doRedirects
      then void $ setCredsRedirect creds
      else do auth <- authenticate creds
              case auth of
                  Authenticated aid -> setSession credsKey $ toPathPiece aid
                  _ -> return ()

-- | same as defaultLayoutJson, but uses authLayout
authLayoutJson
  :: (ToJSON j, MonadAuthHandler master m)
  => m j  -- ^ JSON
  -> m Value
authLayoutJson json = do
   fmap toJSON json

-- | Clears current user credentials for the session.

clearCreds :: (MonadHandler m, YesodAuth (HandlerSite m))
           => m ()
clearCreds = do
--    y <- getYesod
    deleteSession credsKey

getCheckR :: AuthHandler master Value
getCheckR = do
    creds <- maybeAuthId
    setCsrfCookie
    authLayoutJson (return $ jsonCreds creds)
  where
    jsonCreds creds =
        Object $ Map.fromList
            [ (T.pack "logged_in", Bool $ maybe False (const True) creds)
            ]

postLogoutR :: AuthHandler master ()
postLogoutR = clearCreds

-- | Similar to 'maybeAuthId', but additionally look up the value associated
-- with the user\'s database identifier to get the value in the database. This
-- assumes that you are using a Persistent database.
--
-- @since 1.1.0
maybeAuth :: ( YesodAuthPersist master
             , val ~ AuthEntity master
             , Key val ~ AuthId master
             , PersistEntity val
             , Typeable val
             , MonadHandler m
             , HandlerSite m ~ master
             ) => m (Maybe (Entity val))
maybeAuth = fmap (fmap (uncurry Entity)) maybeAuthPair

handlePluginR :: Text -> [Text] -> AuthHandler master Value
handlePluginR plugin pieces = do
    master <- getYesod
    env <- waiRequest
    let method = decodeUtf8With lenientDecode $ W.requestMethod env
    case filter (\x -> apName x == plugin) (authPlugins master) of
        [] -> notFound
        ap:_ -> apDispatch ap method pieces

-- | Similar to 'maybeAuth', but doesn’t assume that you are using a
-- Persistent database.
--
-- @since 1.4.0
maybeAuthPair
  :: ( YesodAuthPersist master
     , Typeable (AuthEntity master)
     , MonadHandler m
     , HandlerSite m ~ master
     )
  => m (Maybe (AuthId master, AuthEntity master))
maybeAuthPair = runMaybeT $ do
    aid <- MaybeT maybeAuthId
    ae  <- MaybeT $ cachedAuth aid
    return (aid, ae)


newtype CachedMaybeAuth val = CachedMaybeAuth { unCachedMaybeAuth :: Maybe val }
    deriving Typeable

-- | Class which states that the given site is an instance of @YesodAuth@
-- and that its @AuthId@ is a lookup key for the full user information in
-- a @YesodPersist@ database.
--
-- The default implementation of @getAuthEntity@ assumes that the @AuthId@
-- for the @YesodAuth@ superclass is in fact a persistent @Key@ for the
-- given value.  This is the common case in Yesod, and means that you can
-- easily look up the full information on a given user.
--
-- @since 1.4.0
class (YesodAuth master, YesodPersist master) => YesodAuthPersist master where
    -- | If the @AuthId@ for a given site is a persistent ID, this will give the
    -- value for that entity. E.g.:
    --
    -- > type AuthId MySite = UserId
    -- > AuthEntity MySite ~ User
    --
    -- @since 1.2.0
    type AuthEntity master :: *
    type AuthEntity master = KeyEntity (AuthId master)

    getAuthEntity :: (MonadHandler m, HandlerSite m ~ master)
                  => AuthId master -> m (Maybe (AuthEntity master))

    default getAuthEntity
        :: ( YesodPersistBackend master ~ backend
           , PersistRecordBackend (AuthEntity master) backend
           , Key (AuthEntity master) ~ AuthId master
           , PersistStore backend
           , MonadHandler m
           , HandlerSite m ~ master
           )
        => AuthId master -> m (Maybe (AuthEntity master))
    getAuthEntity = liftHandler . runDB . get


type family KeyEntity key
type instance KeyEntity (Key x) = x

-- | Similar to 'maybeAuthId', but redirects to a login page if user is not
-- authenticated or responds with error 401 if this is an API client (expecting JSON).
--
-- @since 1.1.0
requireAuthId :: (MonadHandler m, YesodAuth (HandlerSite m)) => m (AuthId (HandlerSite m))
requireAuthId = maybeAuthId >>= maybe handleAuthLack return

-- | Similar to 'maybeAuth', but redirects to a login page if user is not
-- authenticated or responds with error 401 if this is an API client (expecting JSON).
--
-- @since 1.1.0
requireAuth :: ( YesodAuthPersist master
               , val ~ AuthEntity master
               , Key val ~ AuthId master
               , PersistEntity val
               , Typeable val
               , MonadHandler m
               , HandlerSite m ~ master
               ) => m (Entity val)
requireAuth = maybeAuth >>= maybe handleAuthLack return

-- | Similar to 'requireAuth', but not tied to Persistent's 'Entity' type.
-- Instead, the 'AuthId' and 'AuthEntity' are returned in a tuple.
--
-- @since 1.4.0
requireAuthPair
  :: ( YesodAuthPersist master
     , Typeable (AuthEntity master)
     , MonadHandler m
     , HandlerSite m ~ master
     )
  => m (AuthId master, AuthEntity master)
requireAuthPair = maybeAuthPair >>= maybe handleAuthLack return

handleAuthLack :: (YesodAuth (HandlerSite m), MonadHandler m) => m a
handleAuthLack = notAuthenticated

instance YesodAuth master => RenderMessage master AuthMessage where
    renderMessage = renderAuthMessage

data AuthException = InvalidFacebookResponse
    deriving (Show, Typeable)
instance Exception AuthException

instance YesodAuth master => YesodSubDispatch Auth master where
    yesodSubDispatch = $(mkYesodSubDispatch resourcesAuth)

asHtml :: Html -> Html
asHtml = id
