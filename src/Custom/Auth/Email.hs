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
 
module Custom.Auth.Email
      -- * Plugin
  ( authEmail
  , YesodAuthEmail(..)
  , EmailCreds(..)
  , saltPassword
      -- * Routes
  , emailVerificationR
  , isValidPassword
      -- * Types
  , Email
  , VerificationToken
  , VerificationUrl
  , SaltedPassword
  , VerificationStatus
  , Identifier
  ) where

import qualified Yesod.Auth.Util.PasswordStore as PS
import qualified Custom.Auth.Message           as Msg
import qualified Data.Text.Encoding            as TE
import qualified Web.ClientSession             as CS
import qualified Crypto.Nonce                  as Nonce
import qualified Crypto.Hash                   as H
import qualified Data.Text                     as TS
import qualified Data.Text                     as T
import qualified Text.Email.Validate
import           Data.Text.Encoding.Error      (lenientDecode)
import           Data.ByteString.Base16        as B16
import           Control.Applicative           ((<$>))
import           Data.Text.Encoding            (decodeUtf8With, encodeUtf8)
import           System.IO.Unsafe              (unsafePerformIO)
import           Data.Aeson.Types              (Parser, Result (..), parseEither, withObject)
import           Data.ByteArray                (convert)
import           Data.Text                     (Text)
import           Network.HTTP.Types.URI
import           Custom.Auth
import           Yesod.Core

-- | The email verification AuthRoute
emailVerificationR :: Text -> Text -> AuthRoute
emailVerificationR userId verificationToken = PluginR "email" path
  where
    path = "verify" : userId : [verificationToken]

-- | The reset password AuthRoute
resetPasswordR :: Text -> Text -> AuthRoute
resetPasswordR encryptedUserId verificationToken = PluginR "email" path
  where
    path = "reset-password" : encryptedUserId : [verificationToken]

type Email = Text

type VerificationToken = Text

type VerificationUrl = Text

type SaltedPassword = Text

type VerificationStatus = Bool

type Identifier = Text

data EmailCreds site = EmailCreds
  { emailCredsId     :: AuthEmailId site
  , emailCredsAuthId :: Maybe (AuthId site)
  , emailCredsStatus :: VerificationStatus
  , emailCredsVerkey :: Maybe VerificationToken
  , emailCredsEmail  :: Email
  }

class (YesodAuth site, PathPiece (AuthEmailId site), (RenderMessage site Msg.AuthMessage), Show (AuthEmailId site)) =>
      YesodAuthEmail site
  where
  
  type AuthEmailId site
  
  addUnverified :: Email -> VerificationToken -> AuthHandler site (AuthEmailId site)
  
  addUnverifiedWithPassword :: Email -> VerificationToken -> SaltedPassword -> AuthHandler site (AuthEmailId site)
  addUnverifiedWithPassword email verificationToken _ = addUnverified email verificationToken
  
  sendVerifyEmail :: Email -> VerificationToken -> VerificationUrl -> AuthHandler site ()
  
  sendResetPasswordEmail :: Email -> VerificationToken -> VerificationUrl -> AuthHandler site ()
  
  getVerificationToken :: AuthId site -> AuthHandler site (Maybe VerificationToken)
  
  setVerificationToken :: AuthEmailId site -> VerificationToken -> AuthHandler site ()
  
  hashAndSaltPassword :: Text -> AuthHandler site SaltedPassword
  hashAndSaltPassword = liftIO . saltPassword
  
  verifyPassword :: Text -> SaltedPassword -> AuthHandler site Bool
  verifyPassword plain salted = return $ isValidPassword plain salted
  
  -- | Verify the email address on the given account.
  --
  -- __/Warning!/__ If you have persisted the @'AuthEmailId' site@
  -- somewhere, this method should delete that key, or make it unusable
  -- in some fashion. Otherwise, the same key can be used multiple times!
  --
  -- See <https://github.com/yesodweb/yesod/issues/1222>.
  verifyAccount :: AuthId site -> AuthHandler site (Maybe (AuthId site))

  -- | Get the salted password for the given account.
  getPassword :: AuthId site -> AuthHandler site (Maybe SaltedPassword)

  -- | Set the salted password for the given account.
  setPassword :: AuthId site -> SaltedPassword -> AuthHandler site ()

  -- | Get the credentials for the given @Identifier@, which may be either an
  -- email address or some other identification (e.g., username).
  getEmailCreds :: Identifier -> AuthHandler site (Maybe (EmailCreds site))

  -- | Get the email address for the given email ID.
  getEmail :: AuthId site -> AuthHandler site (Maybe Email)

  -- | Generate a random alphanumeric string.
  randomKey :: site -> IO VerificationToken
  randomKey _ = Nonce.nonce128urlT defaultNonceGen

  -- | Check that the given plain-text password meets minimum security standards.
  --
  -- Default: password is at least three characters.
  checkPasswordSecurity :: Text -> AuthHandler site (Either Text ())
  checkPasswordSecurity x
    | TS.length x >= 3 = return $ Right ()
    | otherwise = return $ Left "Password must be at least three characters"

  -- | Response after sending a confirmation email.
  confirmationEmailSentResponse :: Text -> AuthHandler site Value
  confirmationEmailSentResponse identifier = do
    mr <- getMessageRender
    provideJsonMessage (mr msg)
    where
      msg = Msg.ConfirmationEmailSent identifier

  -- | Response after sending a confirmation email.
  resetPasswordEmailSentResponse :: Text -> AuthHandler site Value
  resetPasswordEmailSentResponse identifier = do
    mr <- getMessageRender
    provideJsonMessage (mr msg)
    where
      msg = Msg.ResetPasswordEmailSent identifier

  -- | Additional normalization of email addresses, besides standard canonicalization.
  --
  -- Default: Lower case the email address.
  normalizeEmailAddress :: site -> Text -> Text
  normalizeEmailAddress _ = TS.toLower

authEmail :: (YesodAuthEmail m) => AuthPlugin m
authEmail = AuthPlugin "email" dispatch
  where
    dispatch "POST" ["register"] = postRegisterR >>= sendResponse
    dispatch "POST" ["forgot-password"] = postForgotPasswordR >>= sendResponse
    dispatch "GET" ["verify", encryptedUserId, verificationToken] =
      case fromPathPiece encryptedUserId of
        Nothing      -> notFound
        Just encryptedUserId' -> getEmailVerificationR encryptedUserId' verificationToken >>= sendResponse
    dispatch "POST" ["login"] = postLoginR >>= sendResponse
    dispatch "POST" ["reset-password", encryptedUserId, verificationToken] =
      case fromPathPiece encryptedUserId of
        Nothing -> notFound
        Just encryptedUserId' -> postResetPasswordR encryptedUserId' verificationToken >>= sendResponse
    dispatch _ _ = notFound

encryptAndUrlEncode :: YesodAuthEmail master => Text -> AuthHandler master Text
encryptAndUrlEncode value = do
  key <- liftIO $ CS.getKey "config/client_session_key.aes"
  iv <- liftIO $ CS.randomIV
  return $ TE.decodeUtf8 $ urlEncode True $ CS.encrypt key iv (encodeUtf8 value)

registerHelper ::
     YesodAuthEmail master
  => Bool -- ^ forgot password?
  -> AuthHandler master Value
registerHelper forgotPassword = do
  checkCsrfHeaderOrParam defaultCsrfHeaderName defaultCsrfParamName -- Check if csrf token is added in request
  jsonRegisterForgotPasswordCredsParseResult <-
    do (creds :: Result Value) <- parseCheckJsonBody
       case creds of
         Error errorMessage -> do
           $(logError) $ T.pack errorMessage
           return MalformedRegisterForgotPasswordJSON
         Success val -> do
           $(logInfo) $ T.pack $ show val
           let eitherEmailField = parseEither parseEmailField val
           $(logInfo) $ T.pack $ show eitherEmailField
           case eitherEmailField of
             Left missingEmailError -> do
               $(logError) $ T.pack $ show missingEmailError
               return MissingRegisterForgotPasswordEmail
             Right email -> do
               $(logInfo) $ T.pack $ show email
               if forgotPassword
                 then return $ ForgotPasswordCreds email
                 else do
                   let eitherPasswordField = parseEither parsePasswordField val
                   $(logInfo) $ T.pack $ show eitherPasswordField
                   case eitherPasswordField of
                     Left missingPasswordError -> do
                       $(logError) $ T.pack $ show missingPasswordError
                       return MissingRegisterForgotPasswordPassword
                     Right password -> return $ RegisterCreds email password
  $(logInfo) $ T.pack $ show jsonRegisterForgotPasswordCredsParseResult
  messageRender <- getMessageRender
  y <- getYesod -- It is used to produce randomKey
  emailIdentifier <-
    case jsonRegisterForgotPasswordCredsParseResult of
      MalformedRegisterForgotPasswordJSON -> do
        $(logError) $ messageRender Msg.MalformedJSONMessage
        return $ Left Msg.MalformedJSONMessage
      MissingRegisterForgotPasswordEmail -> do
        $(logError) $ messageRender Msg.MissingEmailMessage
        return $ Left Msg.MissingEmailMessage
      MissingRegisterForgotPasswordPassword -> do
        $(logError) $ messageRender Msg.MissingPasswordMessage
        return $ Left Msg.MissingPasswordMessage
      RegisterCreds email password
        | Just email' <- Text.Email.Validate.canonicalizeEmail (encodeUtf8 email) -- canonicalize email
         -> do
          let loginRegisterCreds =
                RegisterCreds (normalizeEmailAddress y $ decodeUtf8With lenientDecode email') password
          $(logInfo) $ T.pack $ show loginRegisterCreds
          return $ Right loginRegisterCreds
        | otherwise -- or return error message that the value entered as email is not one
         -> do
          $(logError) $ messageRender Msg.InvalidEmailAddress
          return $ Left Msg.InvalidEmailAddress
      ForgotPasswordCreds email
        | Just email' <- Text.Email.Validate.canonicalizeEmail (encodeUtf8 email) -> do
          let forgotPasswordCreds = ForgotPasswordCreds (normalizeEmailAddress y $ decodeUtf8With lenientDecode email')
          $(logInfo) $ T.pack $ show forgotPasswordCreds
          return $ Right forgotPasswordCreds
        | otherwise -> do
          $(logError) $ messageRender Msg.InvalidEmailAddress
          return $ Left Msg.InvalidEmailAddress
  case emailIdentifier of
    Left message -> loginErrorMessageI message
    Right (RegisterCreds email password) -> do
      mecreds <- getEmailCreds email
      registerCreds <-
        case mecreds of
          Just (EmailCreds lid _ verStatus (Just key) email') -> return $ Right (lid, verStatus, key, email')
          Nothing -- The user has not been registered yet
           -> do
            isSecure <- checkPasswordSecurity password
            $(logInfo) $ T.pack $ show isSecure
            case isSecure of
              Left e -> do
                $(logError) e
                return $ Left e
              Right () -> do
                key <- liftIO $ randomKey y
                lid <-
                  do salted <- hashAndSaltPassword password
                     addUnverifiedWithPassword email key salted
                return $ Right (lid, False, key, email)
          _ -> do
            $(logError) $ messageRender $ Msg.UserRowNotInValidState email
            return $ Left $ messageRender Msg.RegistrationFailure
      case registerCreds of
        Right creds1@(_, False, _, _) -> sendConfirmationEmail creds1
        Right (_, True, _, _) -> loginErrorMessageI Msg.AlreadyRegistered
        Left e -> provideJsonMessage e
      where sendConfirmationEmail (lid, _, verificationToken, email') = do
              render <- getUrlRender
              tp <- getRouteToParent
              encryptedAndUrlEncodedUserId <- encryptAndUrlEncode . toPathPiece $ lid
              encryptedAndUrlEncodedVerificationToken <- encryptAndUrlEncode verificationToken
              let verificationUrl = render $ tp $ emailVerificationR encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken
              sendVerifyEmail email' verificationToken verificationUrl
              confirmationEmailSentResponse email'
    Right (ForgotPasswordCreds email) -> do
      mecreds <- getEmailCreds email
      registerCreds <-
        case mecreds of
          Just (EmailCreds lid _ verStatus (Just key) email') -> return $ Just (lid, verStatus, key, email')
          Nothing -> do
            $(logError) $ messageRender $ Msg.NoSuchUser email
            return Nothing
          _ -> do
            $(logError) $ messageRender $ Msg.UserRowNotInValidState email
            return Nothing
      case registerCreds of
        Nothing     -> loginErrorMessageI Msg.ForgotPasswordFailure
        Just creds1 -> sendResetPasswordEmailHandler creds1
      where sendResetPasswordEmailHandler (authId, _, verificationToken, email') = do
              render <- getUrlRender
              tp <- getRouteToParent
              encryptedAndUrlEncodedUserId <- encryptAndUrlEncode . toPathPiece $ authId
              encryptedAndUrlEncodedVerificationToken <- encryptAndUrlEncode verificationToken
              let verificationUrl = render $ tp $ resetPasswordR encryptedAndUrlEncodedUserId encryptedAndUrlEncodedVerificationToken
              sendResetPasswordEmail email' verificationToken verificationUrl
              resetPasswordEmailSentResponse email'
    _ -> do
      $(logError) $ T.pack "Invalid pattern match"
      loginErrorMessageI Msg.RegistrationFailure

postRegisterR :: YesodAuthEmail master => AuthHandler master Value
postRegisterR = registerHelper False

postForgotPasswordR :: YesodAuthEmail master => AuthHandler master Value
postForgotPasswordR = registerHelper True

decryptAndUrlDecode :: YesodAuthEmail master => Text -> AuthHandler master (Maybe Text)
decryptAndUrlDecode value = do
  key <- liftIO $ CS.getKey "config/client_session_key.aes"
  let maybeUserId = CS.decrypt key $ urlDecode True $ encodeUtf8 value
  return $ maybeUserId >>= (\userId ->
    Just $ TE.decodeUtf8 userId)

getEmailVerificationR :: YesodAuthEmail site => Text -> Text -> AuthHandler site Value
getEmailVerificationR urlEncodedEncryptedUserId urlEncodedEncryptedVerificationToken = do
  maybeUserId <- decryptAndUrlDecode urlEncodedEncryptedUserId
  maybeVerificationToken <- decryptAndUrlDecode urlEncodedEncryptedVerificationToken
  messageRender <- getMessageRender
  case maybeUserId of
    Nothing -> do
      $(logError) $ messageRender $ Msg.UnableToDecryptUserId urlEncodedEncryptedUserId
      provideJsonMessage $ messageRender $ Msg.UnableToDecryptUserId urlEncodedEncryptedUserId
    Just userId -> do
      let maybeUserId' = fromPathPiece userId
      case maybeUserId' of
        Nothing -> do
          $(logError) $ (T.pack "Unable to parse path piece ") `T.append` userId
          provideJsonMessage $ (T.pack "Unable to parse path piece ") `T.append` userId
        Just userId' -> do
          realKey <- getVerificationToken userId'
          memail <- getEmail userId'
          case (realKey == maybeVerificationToken, memail) of
            (True, Just email) -> do
              muid <- verifyAccount userId'
              case muid of
                Nothing -> invalidKey messageRender
                Just _ -> do
                  setCreds $ Creds "email-verify" email [("verifiedEmail", email)] -- FIXME uid?
                  let msgAv = Msg.AddressVerified
                  provideJsonMessage $ messageRender msgAv
            _ -> invalidKey messageRender
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
  = MalformedLoginJSON
  | MissingLoginEmail
  | MissingLoginPassword
  | LoginCreds Email
               Password
  deriving (Show)

data JSONRegisterForgotPasswordCredsParseResult
  = MalformedRegisterForgotPasswordJSON
  | MissingRegisterForgotPasswordEmail
  | MissingRegisterForgotPasswordPassword
  | ForgotPasswordCreds Email
  | RegisterCreds Email
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
           return MalformedLoginJSON
         Success val -> do
           $(logInfo) $ T.pack $ show val
           let eitherEmailField = parseEither parseEmailField val
           $(logInfo) $ T.pack $ show eitherEmailField
           case eitherEmailField of
             Left missingEmailError -> do
               $(logError) $ T.pack $ show missingEmailError
               return MissingLoginEmail
             Right email -> do
               $(logInfo) $ T.pack $ show email
               let eitherPasswordField = parseEither parsePasswordField val
               $(logInfo) $ T.pack $ show eitherPasswordField
               case eitherPasswordField of
                 Left missingPasswordError -> do
                   $(logError) $ T.pack $ show missingPasswordError
                   return MissingLoginPassword
                 Right password -> return $ LoginCreds email password
  $(logInfo) $ T.pack $ show jsonLoginCredsParseResult
  messageRender <- getMessageRender
  case jsonLoginCredsParseResult of
    MalformedLoginJSON -> loginErrorMessageI Msg.MalformedJSONMessage
    MissingLoginEmail -> loginErrorMessageI Msg.MissingEmailMessage
    MissingLoginPassword -> loginErrorMessageI Msg.MissingPasswordMessage
    LoginCreds email password
      | Just email' <- Text.Email.Validate.canonicalizeEmail (encodeUtf8 email) -> do
        emailCreds <- getEmailCreds $ decodeUtf8With lenientDecode email'
        loginResult <-
          case (emailCreds >>= emailCredsAuthId, emailCredsEmail <$> emailCreds, emailCredsStatus <$> emailCreds) of
            (Just aid, Just email'', Just True) -> do
              mrealpass <- getPassword aid
              case mrealpass of
                Nothing -> return $ PasswordNotSet email''
                Just realpass -> do
                  passValid <- verifyPassword password realpass
                  return $
                    if passValid
                      then LoginValidationSuccess email''
                      else PasswordMismatch email''
            (_, Just email'', Just False) -> do
              $(logError) $ messageRender $ Msg.AccountNotVerified email''
              return $ AccountNotVerified email''
            (Nothing, Just email'', _) -> do
              $(logError) $ messageRender $ Msg.LoginFailureEmail email''
              return $ LoginFailureEmail email''
            _ -> do
              $(logError) $ messageRender Msg.LoginFailure
              return LoginFailure
        let isEmail = Text.Email.Validate.isValid $ encodeUtf8 email
        case loginResult of
          LoginValidationSuccess email'' ->
            setCredsWithResponse $
            Creds
              (if isEmail
                 then "email"
                 else "username")
              email''
              [("verifiedEmail", email'')]
          PasswordNotSet email'' -> do
            $(logError) $ messageRender $ Msg.PasswordNotSet email''
            loginErrorMessageI $
              if isEmail
                then Msg.InvalidEmailPass
                else Msg.InvalidUsernamePass
          PasswordMismatch email'' -> do
            $(logError) $ messageRender $ Msg.PasswordMismatch email''
            loginErrorMessageI $
              if isEmail
                then Msg.InvalidEmailPass
                else Msg.InvalidUsernamePass
          AccountNotVerified email'' -> do
            $(logError) $ messageRender $ Msg.AccountNotVerified email''
            loginErrorMessageI $ Msg.AccountNotVerified email''
          LoginFailureEmail email'' -> do
            $(logError) $ messageRender $ Msg.LoginFailureEmail email''
            loginErrorMessageI Msg.LoginFailure
          LoginFailure -> do
            $(logError) $ messageRender Msg.LoginFailure
            loginErrorMessageI Msg.LoginFailure
      | otherwise -> do
        $(logError) $ messageRender Msg.InvalidEmailAddress
        loginErrorMessageI Msg.InvalidEmailAddress

parseNewPasswordField :: Value -> Parser Text
parseNewPasswordField =
  withObject
    "newPassword"
    (\obj -> do
       newPassword <- obj .: "new"
       return newPassword)

parseConfirmPasswordField :: Value -> Parser Text
parseConfirmPasswordField =
  withObject
    "confirmPassword"
    (\obj -> do
       confirm <- obj .: "confirm"
       return confirm)

data JSONResetPasswordCredsParseResult
  = MalformedResetPasswordJSON
  | MissingNewPassword
  | MissingConfirmPassword
  | ResetPasswordCreds Password
                       Password
  deriving (Show)

postResetPasswordR :: YesodAuthEmail site => Text -> Text -> AuthHandler site Value
postResetPasswordR urlEncodedEncryptedUserId urlEncodedEncryptedVerificationToken = do
  (creds :: Result Value) <- parseCheckJsonBody
  jsonResetPasswordCredsParseResult <-
       case creds of
         Error errorMessage -> do
           $(logError) $ T.pack errorMessage
           return MalformedResetPasswordJSON
         Success val -> do
           $(logInfo) $ T.pack $ show val
           let eitherNewPasswordField = parseEither parseNewPasswordField val
           $(logInfo) $ T.pack $ show eitherNewPasswordField
           case eitherNewPasswordField of
             Left missingNewPasswordError -> do
               $(logError) $ T.pack $ show missingNewPasswordError
               return MissingNewPassword
             Right newPassword -> do
               $(logInfo) $ T.pack $ show newPassword
               let eitherConfirmPasswordField = parseEither parseConfirmPasswordField val
               $(logInfo) $ T.pack $ show eitherConfirmPasswordField
               case eitherConfirmPasswordField of
                 Left missingConfirmPasswordError -> do
                   $(logError) $ T.pack $ show missingConfirmPasswordError
                   return MissingConfirmPassword
                 Right confirmPassword ->
                   return $ ResetPasswordCreds newPassword confirmPassword
  maybeUserId <- decryptAndUrlDecode urlEncodedEncryptedUserId
  messageRender <- getMessageRender
  case maybeUserId of
    Nothing -> do
      $(logError) $ messageRender $ Msg.UnableToDecryptUserId urlEncodedEncryptedUserId
      provideJsonMessage $ messageRender $ Msg.UnableToDecryptUserId urlEncodedEncryptedUserId
    Just userId -> do
      maybeVerificationToken <- decryptAndUrlDecode urlEncodedEncryptedVerificationToken
      case maybeVerificationToken of
        Nothing -> do
          $(logError) $ messageRender $ Msg.UnableToDecryptUserId urlEncodedEncryptedUserId
          provideJsonMessage $ messageRender $ Msg.UnableToDecryptUserId urlEncodedEncryptedUserId
        Just verificationToken ->
          case jsonResetPasswordCredsParseResult of
            MalformedResetPasswordJSON -> loginErrorMessageI Msg.MalformedJSONMessage
            MissingNewPassword -> do
              $(logError) $ messageRender $ Msg.MissingNewPasswordInternalMessage $ T.pack $ show userId
              loginErrorMessageI Msg.MissingNewPasswordMessage
            MissingConfirmPassword -> do
              $(logError) $ messageRender $ Msg.MissingConfirmPasswordInternalMessage $ T.pack $ show userId
              loginErrorMessageI Msg.MissingConfirmPasswordMessage
            ResetPasswordCreds newPassword confirmPassword
              | newPassword == confirmPassword -> do
                let maybeUserId' = fromPathPiece userId
                case maybeUserId' of
                  Nothing -> do
                    $(logError) $ (T.pack "Unable to parse path piece ") `T.append` userId
                    provideJsonMessage $ (T.pack "Unable to parse path piece ") `T.append` userId
                  Just userId' -> do
                    isSecure <- checkPasswordSecurity newPassword
                    case isSecure of
                      Left e -> do
                        $(logError) e
                        loginErrorMessage e
                      Right () -> do
                        storedVerificationKey <- getVerificationToken userId'
                        case (storedVerificationKey, verificationToken) of
                          (Just value, vk)
                            | value == vk -> do
                              salted <- hashAndSaltPassword newPassword
                              $(logInfo) $ T.pack $ "New salted password for user with userId " ++ show userId ++ " is " ++ T.unpack salted
                              setPassword userId' salted
                              $(logInfo) $ T.pack $ "New password updated for user with userId " ++ show userId
                              messageJson200 $ messageRender Msg.PassUpdated
                            | otherwise -> do
                              $(logError) $ messageRender $ Msg.InvalidVerificationKeyInternalMessage (T.pack $ show userId)
                                vk value
                              loginErrorMessageI Msg.InvalidVerificationKey
                          (Nothing, vk) -> do
                            $(logError) $ messageRender $ Msg.MissingVerificationKeyInternalMessage (T.pack $ show userId) vk
                            loginErrorMessageI Msg.InvalidVerificationKey
              | otherwise -> do
                $(logError) $ messageRender $ Msg.PassMismatchInternalMessage $ T.pack $ show userId
                loginErrorMessageI Msg.PassMismatch

saltLength :: Int
saltLength = 5

-- | Salt a password with a randomly generated salt.
saltPassword :: Text -> IO Text
saltPassword = fmap (decodeUtf8With lenientDecode) . flip PS.makePassword 16 . encodeUtf8

saltPassword' :: String -> String -> String
saltPassword' salt pass =
  salt ++
  T.unpack (TE.decodeUtf8 $ B16.encode $ convert (H.hash (TE.encodeUtf8 $ T.pack $ salt ++ pass) :: H.Digest H.MD5))

isValidPassword ::
     Text -- ^ cleartext password
  -> SaltedPassword -- ^ salted password
  -> Bool
isValidPassword ct salted = PS.verifyPassword (encodeUtf8 ct) (encodeUtf8 salted) || isValidPassword' ct salted

isValidPassword' ::
     Text -- ^ cleartext password
  -> SaltedPassword -- ^ salted password
  -> Bool
isValidPassword' clear' salted' =
  let salt = take saltLength salted
   in salted == saltPassword' salt clear
  where
    clear = TS.unpack clear'
    salted = TS.unpack salted'

-- See https://github.com/yesodweb/yesod/issues/1245 for discussion on this
-- use of unsafePerformIO.
defaultNonceGen :: Nonce.Generator
defaultNonceGen = unsafePerformIO Nonce.new

{-# NOINLINE defaultNonceGen #-}
