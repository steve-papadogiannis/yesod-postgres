{-# LANGUAGE ConstrainedClassMethods #-}
{-# LANGUAGE DeriveDataTypeable      #-}
{-# LANGUAGE FlexibleContexts        #-}
{-# LANGUAGE OverloadedStrings       #-}
{-# LANGUAGE PatternGuards           #-}
{-# LANGUAGE Rank2Types              #-}
{-# LANGUAGE ScopedTypeVariables     #-}
{-# LANGUAGE TemplateHaskell         #-}
{-# LANGUAGE TypeFamilies            #-}

-- | A Yesod plugin for Authentication via e-mail
--
-- This plugin works out of the box by only setting a few methods on
-- the type class that tell the plugin how to interoperate with your
-- user data storage (your database).  However, almost everything is
-- customizeable by setting more methods on the type class.  In
-- addition, you can send all the form submissions via JSON and
-- completely control the user's flow.
--
-- This is a standard registration e-mail flow
--
-- 1. A user registers a new e-mail address, and an e-mail is sent there
-- 2. The user clicks on the registration link in the e-mail. Note that
--   at this point they are actually logged in (without a
--   password). That means that when they log out they will need to
--  reset their password.
-- 3. The user sets their password and is redirected to the site.
-- 4. The user can now
--
--     * logout and sign in
--     * reset their password
--
-- = Using JSON Endpoints
--
-- We are assuming that you have declared auth route as follows
--
-- @
--    /auth AuthR Auth getAuth
-- @
--
-- If you are using a different route, then you have to adjust the
-- endpoints accordingly.
--
--     * Registration
--
-- @
--       Endpoint: \/auth\/page\/email\/register
--       Method: POST
--       JSON Data: {
--                      "email": "myemail@domain.com",
--                      "password": "myStrongPassword" (optional)
--                  }
-- @
--
--     * Forgot password
--
-- @
--       Endpoint: \/auth\/page\/email\/forgot-password
--       Method: POST
--       JSON Data: { "email": "myemail@domain.com" }
-- @
--
--     * Login
--
-- @
--       Endpoint: \/auth\/page\/email\/login
--       Method: POST
--       JSON Data: {
--                      "email": "myemail@domain.com",
--                      "password": "myStrongPassword"
--                  }
-- @
--
--     * Set new password
--
-- @
--       Endpoint: \/auth\/page\/email\/set-password
--       Method: POST
--       JSON Data: {
--                       "new": "newPassword",
--                       "confirm": "newPassword",
--                       "current": "currentPassword"
--                  }
-- @
--
--  Note that in the set password endpoint, the presence of the key
--  "current" is dependent on how the 'needOldPassword' is defined in
--  the instance for 'YesodAuthEmail'.
module Custom.Auth.Email
      -- * Plugin
  ( authEmail
  , YesodAuthEmail(..)
  , EmailCreds(..)
  , saltPass
      -- * Routes
  , verifyR
  , isValidPass
      -- * Types
  , Email
  , VerKey
  , VerUrl
  , SaltedPass
  , VerStatus
  , Identifier
     -- * Misc
  , loginLinkKey
  , setLoginLinkKey
  ) where

import           Control.Applicative           ((<$>), (<*>))
import qualified Crypto.Hash                   as H
import qualified Crypto.Nonce                  as Nonce
import           Custom.Auth
import qualified Custom.Auth.Message           as Msg
import           Data.Aeson.Types              (Parser, Result (..),
                                                parseEither, parseMaybe,
                                                withObject, (.:?))
import           Data.ByteArray                (convert)
import           Data.ByteString.Base16        as B16
import           Data.Maybe                    (isJust)
import           Data.Text                     (Text)
import qualified Data.Text                     as TS
import qualified Data.Text                     as T
import           Data.Text.Encoding            (decodeUtf8With, encodeUtf8)
import qualified Data.Text.Encoding            as TE
import           Data.Text.Encoding.Error      (lenientDecode)
import           Data.Time                     (addUTCTime, getCurrentTime)
import           Safe                          (readMay)
import           System.IO.Unsafe              (unsafePerformIO)
import qualified Text.Email.Validate
import qualified Yesod.Auth.Util.PasswordStore as PS
import           Yesod.Core
import           Yesod.Form

verifyURLHasSetPassText :: Text
verifyURLHasSetPassText = "has-set-pass"

verifyR :: Text -> Text -> AuthRoute
verifyR eid verkey = PluginR "email" path
  where
    path = "verify" : eid : verkey : [verifyURLHasSetPassText]

type Email = Text

type VerKey = Text

type VerUrl = Text

type SaltedPass = Text

type VerStatus = Bool

type Identifier = Text

data EmailCreds site = EmailCreds
  { emailCredsId     :: AuthEmailId site
  , emailCredsAuthId :: Maybe (AuthId site)
  , emailCredsStatus :: VerStatus
  , emailCredsVerkey :: Maybe VerKey
  , emailCredsEmail  :: Email
  }

class (YesodAuth site, PathPiece (AuthEmailId site), (RenderMessage site Msg.AuthMessage)) =>
      YesodAuthEmail site
  where
  type AuthEmailId site
  addUnverified :: Email -> VerKey -> AuthHandler site (AuthEmailId site)
  addUnverifiedWithPass :: Email -> VerKey -> SaltedPass -> AuthHandler site (AuthEmailId site)
  addUnverifiedWithPass email verkey _ = addUnverified email verkey
  sendVerifyEmail :: Email -> VerKey -> VerUrl -> AuthHandler site ()
  getVerifyKey :: AuthEmailId site -> AuthHandler site (Maybe VerKey)
  setVerifyKey :: AuthEmailId site -> VerKey -> AuthHandler site ()
  hashAndSaltPassword :: Text -> AuthHandler site SaltedPass
  hashAndSaltPassword = liftIO . saltPass
  verifyPassword :: Text -> SaltedPass -> AuthHandler site Bool
  verifyPassword plain salted = return $ isValidPass plain salted
    -- | Verify the email address on the given account.
    --
    -- __/Warning!/__ If you have persisted the @'AuthEmailId' site@
    -- somewhere, this method should delete that key, or make it unusable
    -- in some fashion. Otherwise, the same key can be used multiple times!
    --
    -- See <https://github.com/yesodweb/yesod/issues/1222>.
    --
    -- @since 1.1.0
  verifyAccount :: AuthEmailId site -> AuthHandler site (Maybe (AuthId site))
    -- | Get the salted password for the given account.
    --
    -- @since 1.1.0
  getPassword :: AuthId site -> AuthHandler site (Maybe SaltedPass)
    -- | Set the salted password for the given account.
    --
    -- @since 1.1.0
  setPassword :: AuthId site -> SaltedPass -> AuthHandler site ()
    -- | Get the credentials for the given @Identifier@, which may be either an
    -- email address or some other identification (e.g., username).
    --
    -- @since 1.2.0
  getEmailCreds :: Identifier -> AuthHandler site (Maybe (EmailCreds site))
    -- | Get the email address for the given email ID.
    --
    -- @since 1.1.0
  getEmail :: AuthEmailId site -> AuthHandler site (Maybe Email)
    -- | Generate a random alphanumeric string.
    --
    -- @since 1.1.0
  randomKey :: site -> IO VerKey
  randomKey _ = Nonce.nonce128urlT defaultNonceGen
    -- | Does the user need to provide the current password in order to set a
    -- new password?
    --
    -- Default: if the user logged in via an email link do not require a password.
    --
    -- @since 1.2.1
  needOldPassword :: AuthId site -> AuthHandler site Bool
  needOldPassword aid' = do
    mkey <- lookupSession loginLinkKey
    case mkey >>= readMay . TS.unpack of
      Just (aidT, time)
        | Just aid <- fromPathPiece aidT
        , toPathPiece (aid `asTypeOf` aid') == toPathPiece aid' -> do
          now <- liftIO getCurrentTime
          return $ addUTCTime (60 * 30) time <= now
      _ -> return True
    -- | Check that the given plain-text password meets minimum security standards.
    --
    -- Default: password is at least three characters.
  checkPasswordSecurity :: AuthId site -> Text -> AuthHandler site (Either Text ())
  checkPasswordSecurity _ x
    | TS.length x >= 3 = return $ Right ()
    | otherwise = return $ Left "Password must be at least three characters"
    -- | Response after sending a confirmation email.
    --
    -- @since 1.2.2
  confirmationEmailSentResponse :: Text -> AuthHandler site Value
  confirmationEmailSentResponse identifier = do
    mr <- getMessageRender
    provideJsonMessage (mr msg)
    where
      msg = Msg.ConfirmationEmailSent identifier
    -- | If a response is set, it will be used when an already-verified email
    -- tries to re-register. Otherwise, `confirmationEmailSentResponse` will be
    -- used.
    --
    -- @since 1.6.4
  emailPreviouslyRegisteredResponse :: MonadAuthHandler site m => Text -> Maybe (m Value)
  emailPreviouslyRegisteredResponse _ = Nothing
    -- | Additional normalization of email addresses, besides standard canonicalization.
    --
    -- Default: Lower case the email address.
    --
    -- @since 1.2.3
  normalizeEmailAddress :: site -> Text -> Text
  normalizeEmailAddress _ = TS.toLower

authEmail :: (YesodAuthEmail m) => AuthPlugin m
authEmail = AuthPlugin "email" dispatch
  where
    dispatch "POST" ["register"] = postRegisterR >>= sendResponse
    dispatch "POST" ["forgot-password"] = postForgotPasswordR >>= sendResponse
    dispatch "GET" ["verify", eid, verkey] =
      case fromPathPiece eid of
        Nothing   -> notFound
        Just eid' -> getVerifyR eid' verkey >>= sendResponse
    dispatch "POST" ["login"] = postLoginR >>= sendResponse
    dispatch "POST" ["set-password"] = postPasswordR >>= sendResponse
    dispatch _ _ = notFound

parseRegister :: Value -> Parser (Text, Maybe Text)
parseRegister =
  withObject
    "email"
    (\obj -> do
       email <- obj .: "email"
       pass <- obj .:? "password"
       return (email, pass))

registerHelper ::
     YesodAuthEmail master
  => Bool -- ^ allow usernames?
  -> Bool -- ^ forgot password?
  -> AuthHandler master Value
registerHelper allowUsername forgotPassword = do
  y <- getYesod
  checkCsrfHeaderOrParam defaultCsrfHeaderName defaultCsrfParamName
  result <- runInputPostResult $ (,) <$> ireq textField "email" <*> iopt textField "password"
  creds <-
    case result of
      FormSuccess (iden, pass) -> return $ Just (iden, pass)
      _ -> do
        (creds :: Result Value) <- parseCheckJsonBody
        return $
          case creds of
            Error _     -> Nothing
            Success val -> parseMaybe parseRegister val
  let eidentifier =
        case creds of
          Nothing -> Left Msg.NoIdentifierProvided
          Just (x, _)
            | Just x' <- Text.Email.Validate.canonicalizeEmail (encodeUtf8 x) ->
              Right $ normalizeEmailAddress y $ decodeUtf8With lenientDecode x'
            | allowUsername -> Right $ TS.strip x
            | otherwise -> Left Msg.InvalidEmailAddress
  let mpass =
        case (forgotPassword, creds) of
          (False, Just (_, mp)) -> mp
          _                     -> Nothing
  case eidentifier of
    Left route -> loginErrorMessageI route
    Right identifier -> do
      mecreds <- getEmailCreds identifier
      registerCreds <-
        case mecreds of
          Just (EmailCreds lid _ verStatus (Just key) email) -> return $ Just (lid, verStatus, key, email)
          Just (EmailCreds lid _ verStatus Nothing email) -> do
            key <- liftIO $ randomKey y
            setVerifyKey lid key
            return $ Just (lid, verStatus, key, email)
          Nothing
            | allowUsername -> return Nothing
            | otherwise -> do
              key <- liftIO $ randomKey y
              lid <-
                case mpass of
                  Just pass -> do
                    salted <- hashAndSaltPassword pass
                    addUnverifiedWithPass identifier key salted
                  _ -> addUnverified identifier key
              return $ Just (lid, False, key, identifier)
      case registerCreds of
        Nothing -> loginErrorMessageI (Msg.IdentifierNotFound identifier)
        Just creds1@(_, False, _, _) -> sendConfirmationEmail creds1
        Just creds1@(_, True, _, _) ->
          if forgotPassword
            then sendConfirmationEmail creds1
            else case emailPreviouslyRegisteredResponse identifier of
                   Just response -> response
                   Nothing       -> sendConfirmationEmail creds1
      where sendConfirmationEmail (lid, _, verKey, email) = do
              render <- getUrlRender
              tp <- getRouteToParent
              let verUrl = render $ tp $ verifyR (toPathPiece lid) verKey
              sendVerifyEmail email verKey verUrl
              confirmationEmailSentResponse identifier

postRegisterR :: YesodAuthEmail master => AuthHandler master Value
postRegisterR = registerHelper False False

postForgotPasswordR :: YesodAuthEmail master => AuthHandler master Value
postForgotPasswordR = registerHelper True True

getVerifyR :: YesodAuthEmail site => AuthEmailId site -> Text -> AuthHandler site Value
getVerifyR lid key = do
  realKey <- getVerifyKey lid
  memail <- getEmail lid
  mr <- getMessageRender
  case (realKey == Just key, memail) of
    (True, Just email) -> do
      muid <- verifyAccount lid
      case muid of
        Nothing -> invalidKey mr
        Just uid -> do
          setCreds False $ Creds "email-verify" email [("verifiedEmail", email)] -- FIXME uid?
          setLoginLinkKey uid
          let msgAv = Msg.AddressVerified
          provideJsonMessage $ mr msgAv
    _ -> invalidKey mr
  where
    msgIk = Msg.InvalidKey
    invalidKey mr = messageJson401 (mr msgIk)

parseEmailField :: Value -> Parser Text
parseEmailField =
  withObject
    "email"
    (\obj -> do
       email' <- obj .: "email"
       return email')

parsePasswordField :: Value -> Parser Text
parsePasswordField =
  withObject
    "password"
    (\obj -> do
       password' <- obj .: "password"
       return password')

type Password = Text

data JSONLoginCredsParseResult
  = MalformedJSON
  | MissingEmail
  | MissingPassword
  | LoginCreds Email
               Password
  deriving (Show)

data LoginResult
  = PasswordNotSet Email
  | AccountNotVerified Email
  | PasswordMismatch Email
  | LoginFailureEmail Email
  | LoginFailure
  | LoginValidationSuccess Email
  deriving (Show)

postLoginR :: YesodAuthEmail master => AuthHandler master Value
postLoginR = do
  jsonLoginCredsParseResult <-
    do (creds :: Result Value) <- parseCheckJsonBody
       case creds of
         Error errorMessage -> do
           $(logError) $ T.pack errorMessage
           return MalformedJSON
         Success val -> do
           $(logInfo) $ T.pack $ show val
           let eitherEmailField = parseEither parseEmailField val
           $(logInfo) $ T.pack $ show eitherEmailField
           case eitherEmailField of
             Left missingEmailError -> do
               $(logError) $ T.pack $ show missingEmailError
               return MissingEmail
             Right email -> do
               $(logInfo) $ T.pack $ show email
               let eitherPasswordField = parseEither parsePasswordField val
               $(logInfo) $ T.pack $ show eitherPasswordField
               case eitherPasswordField of
                 Left missingPasswordError -> do
                   $(logError) $ T.pack $ show missingPasswordError
                   return MissingPassword
                 Right password -> do
                   return $ LoginCreds email password
  $(logInfo) $ T.pack $ show jsonLoginCredsParseResult
  messageRender <- getMessageRender
  case jsonLoginCredsParseResult of
    MalformedJSON -> loginErrorMessageI Msg.MalformedJSONMessage
    MissingEmail -> loginErrorMessageI Msg.MissingEmailMessage
    MissingPassword -> loginErrorMessageI Msg.MissingPasswordMessage
    LoginCreds email password -> do
      emailCreds <- getEmailCreds email
      loginResult <-
        case (emailCreds >>= emailCredsAuthId, emailCredsEmail <$> emailCreds, emailCredsStatus <$> emailCreds) of
          (Just aid, Just email', Just True) -> do
            mrealpass <- getPassword aid
            case mrealpass of
              Nothing -> return $ PasswordNotSet email'
              Just realpass -> do
                passValid <- verifyPassword password realpass
                return $
                  if passValid
                    then LoginValidationSuccess email'
                    else PasswordMismatch email'
          (_, Just email', Just False) -> do
            $(logError) $ messageRender $ Msg.AccountNotVerified email'
            return $ AccountNotVerified email'
          (Nothing, Just email', _) -> do
            $(logError) $ messageRender $ Msg.LoginFailureEmail email'
            return $ LoginFailureEmail email'
          _ -> do
            $(logError) $ messageRender $ Msg.LoginFailure
            return $ LoginFailure
      let isEmail = Text.Email.Validate.isValid $ encodeUtf8 email
      case loginResult of
        LoginValidationSuccess email' ->
          setCredsRedirect $
          Creds
            (if isEmail
               then "email"
               else "username")
            email'
            [("verifiedEmail", email')]
        PasswordNotSet email' -> do
          $(logError) $ messageRender $ Msg.PasswordNotSet email'
          loginErrorMessageI $
            if isEmail
              then Msg.InvalidEmailPass
              else Msg.InvalidUsernamePass
        PasswordMismatch email' -> do
          $(logError) $ messageRender $ Msg.PasswordMismatch email'
          loginErrorMessageI $
            if isEmail
              then Msg.InvalidEmailPass
              else Msg.InvalidUsernamePass
        AccountNotVerified email' -> do
          $(logError) $ messageRender $ Msg.AccountNotVerified email'
          loginErrorMessageI $ Msg.AccountNotVerified email'
        LoginFailureEmail email' -> do
          $(logError) $ messageRender $ Msg.LoginFailureEmail email'
          loginErrorMessageI $ Msg.LoginFailure
        LoginFailure -> do
          $(logError) $ messageRender $ Msg.LoginFailure
          loginErrorMessageI $ Msg.LoginFailure

--getPasswordR :: YesodAuthEmail master => AuthHandler master Value
--getPasswordR = do
--    maid <- maybeAuthId
--    case maid of
--        Nothing -> loginErrorMessageI Msg.BadSetPass
--        Just _ -> do
--            needOld <- maybe (return True) needOldPassword maid
--            provideJsonMessage ("Ok" :: Text)
parsePassword :: Value -> Parser (Text, Text, Maybe Text)
parsePassword =
  withObject
    "password"
    (\obj -> do
       email' <- obj .: "new"
       pass <- obj .: "confirm"
       curr <- obj .:? "current"
       return (email', pass, curr))

postPasswordR :: YesodAuthEmail master => AuthHandler master Value
postPasswordR = do
  maid <- maybeAuthId
  (creds :: Result Value) <- parseCheckJsonBody
  let jcreds =
        case creds of
          Error _     -> Nothing
          Success val -> parseMaybe parsePassword val
  let doJsonParsing = isJust jcreds
  case maid of
    Nothing -> loginErrorMessageI Msg.BadSetPass
    Just aid -> do
      needOld <- needOldPassword aid
      if not needOld
        then confirmPassword aid jcreds
        else do
          res <- runInputPostResult $ ireq textField "current"
          let fcurrent =
                case res of
                  FormSuccess currentPass -> Just currentPass
                  _                       -> Nothing
          let current =
                if doJsonParsing
                  then getThird jcreds
                  else fcurrent
          mrealpass <- getPassword aid
          case (mrealpass, current) of
            (Nothing, _) -> loginErrorMessage "You do not currently have a password set on your account"
            (_, Nothing) -> loginErrorMessageI Msg.BadSetPass
            (Just realpass, Just current') -> do
              passValid <- verifyPassword current' realpass
              if passValid
                then confirmPassword aid jcreds
                else loginErrorMessage "Invalid current password, please try again"
  where
    msgOk = Msg.PassUpdated
    getThird (Just (_, _, t)) = t
    getThird Nothing          = Nothing
    getNewConfirm (Just (a, b, _)) = Just (a, b)
    getNewConfirm _                = Nothing
    confirmPassword aid jcreds = do
      res <- runInputPostResult $ (,) <$> ireq textField "new" <*> ireq textField "confirm"
      let creds =
            if isJust jcreds
              then getNewConfirm jcreds
              else case res of
                     FormSuccess res' -> Just res'
                     _                -> Nothing
      case creds of
        Nothing -> loginErrorMessageI Msg.PassMismatch
        Just (new, confirm) ->
          if new /= confirm
            then loginErrorMessageI Msg.PassMismatch
            else do
              isSecure <- checkPasswordSecurity aid new
              case isSecure of
                Left e -> loginErrorMessage e
                Right () -> do
                  salted <- hashAndSaltPassword new
                  setPassword aid salted
                  deleteSession loginLinkKey
                  mr <- getMessageRender
                  provideJsonMessage (mr msgOk)

saltLength :: Int
saltLength = 5

-- | Salt a password with a randomly generated salt.
saltPass :: Text -> IO Text
saltPass = fmap (decodeUtf8With lenientDecode) . flip PS.makePassword 16 . encodeUtf8

saltPass' :: String -> String -> String
saltPass' salt pass =
  salt ++
  T.unpack (TE.decodeUtf8 $ B16.encode $ convert (H.hash (TE.encodeUtf8 $ T.pack $ salt ++ pass) :: H.Digest H.MD5))

isValidPass ::
     Text -- ^ cleartext password
  -> SaltedPass -- ^ salted password
  -> Bool
isValidPass ct salted = PS.verifyPassword (encodeUtf8 ct) (encodeUtf8 salted) || isValidPass' ct salted

isValidPass' ::
     Text -- ^ cleartext password
  -> SaltedPass -- ^ salted password
  -> Bool
isValidPass' clear' salted' =
  let salt = take saltLength salted
   in salted == saltPass' salt clear
  where
    clear = TS.unpack clear'
    salted = TS.unpack salted'

-- | Session variable set when user logged in via a login link. See
-- 'needOldPassword'.
--
-- @since 1.2.1
loginLinkKey :: Text
loginLinkKey = "_AUTH_EMAIL_LOGIN_LINK"

-- | Set 'loginLinkKey' to the current time.
--
-- @since 1.2.1
--setLoginLinkKey :: (MonadHandler m) => AuthId site -> m ()
setLoginLinkKey :: (MonadHandler m, YesodAuthEmail (HandlerSite m)) => AuthId (HandlerSite m) -> m ()
setLoginLinkKey aid = do
  now <- liftIO getCurrentTime
  setSession loginLinkKey $ TS.pack $ show (toPathPiece aid, now)

-- See https://github.com/yesodweb/yesod/issues/1245 for discussion on this
-- use of unsafePerformIO.
defaultNonceGen :: Nonce.Generator
defaultNonceGen = unsafePerformIO Nonce.new

{-# NOINLINE defaultNonceGen #-}
