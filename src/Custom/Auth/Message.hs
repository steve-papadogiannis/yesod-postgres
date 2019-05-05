{-# LANGUAGE OverloadedStrings #-}

module Custom.Auth.Message
  ( AuthMessage(..)
  , defaultMessage
  , englishMessage
  ) where

import           Data.Monoid (mappend)
import           Data.Text   (Text)

data AuthMessage
  = NoOpenID
  | LoginOpenID
  | LoginGoogle
  | LoginYahoo
  | Email
  | UserName
  | IdentifierNotFound Text
  | Password
  | Register
  | RegisterLong
  | EnterEmail
  | ConfirmationEmailSentTitle
  | ConfirmationEmailSent Text
  | AddressVerified
  | InvalidKeyTitle
  | InvalidKey
  | InvalidEmailPass
  | BadSetPass
  | SetPassTitle
  | SetPass
  | NewPass
  | ConfirmPass
  | PassMismatch
  | PassUpdated
  | Facebook
  | LoginViaEmail
  | InvalidLogin
  | NowLoggedIn
  | LoginTitle
  | PleaseProvideUsername
  | PleaseProvidePassword
  | NoIdentifierProvided
  | InvalidEmailAddress
  | PasswordResetTitle
  | ProvideIdentifier
  | SendPasswordResetEmail
  | PasswordResetPrompt
  | CurrentPassword
  | InvalidUsernamePass
  | Logout
  | LogoutTitle
  | AuthError
  | MalformedJSONMessage
  | MissingEmailMessage
  | MissingPasswordMessage
  | AccountNotVerified Text
  | PasswordNotSet Text
  | PasswordMismatch Text
  | LoginFailureEmail Text
  | LoginFailure
  | AlreadyRegistered
  | UserRowNotInValidState Text
  | RegistrationFailure
  | ForgotPasswordFailure
  | ResetPasswordEmailSent Text
  | MissingNewPasswordInternalMessage Text
  | MissingNewPasswordMessage
  | MissingConfirmPasswordInternalMessage Text
  | MissingConfirmPasswordMessage
  | PassMismatchInternalMessage Text
  | InvalidVerificationKeyInternalMessage Text Text Text
  | InvalidVerificationKey
  | MissingVerificationKeyInternalMessage Text Text
  | UnableToDecryptUserId Text
  | NoSuchUser Text

{-# DEPRECATED
Logout "Please, use LogoutTitle instead."
 #-}

-- | Defaults to 'englishMessage'.
defaultMessage :: AuthMessage -> Text
defaultMessage = englishMessage

englishMessage :: AuthMessage -> Text
englishMessage NoOpenID = "No OpenID identifier found"
englishMessage LoginOpenID = "Log in via OpenID"
englishMessage LoginGoogle = "Log in via Google"
englishMessage LoginYahoo = "Log in via Yahoo"
englishMessage Email = "Email"
englishMessage UserName = "User name"
englishMessage Password = "Password"
englishMessage CurrentPassword = "Current Password"
englishMessage Register = "Register"
englishMessage RegisterLong = "Register a new account"
englishMessage EnterEmail = "Enter your e-mail address below, and a confirmation e-mail will be sent to you."
englishMessage ConfirmationEmailSentTitle = "Confirmation e-mail sent"
englishMessage (ConfirmationEmailSent email) =
  "A confirmation e-mail has been sent to " `mappend` email `mappend` "."
englishMessage AddressVerified = "Address verified"
englishMessage InvalidKeyTitle = "Invalid verification key"
englishMessage InvalidKey = "I'm sorry, but that was an invalid verification key."
englishMessage InvalidEmailPass = "Invalid email/password combination"
englishMessage BadSetPass = "You must be logged in to set a password"
englishMessage SetPassTitle = "Set password"
englishMessage SetPass = "Set a new password"
englishMessage NewPass = "New password"
englishMessage ConfirmPass = "Confirm"
englishMessage PassMismatch = "Passwords did not match, please try again"
englishMessage PassUpdated = "Password updated"
englishMessage Facebook = "Log in with Facebook"
englishMessage LoginViaEmail = "Log in via email"
englishMessage InvalidLogin = "Invalid login"
englishMessage NowLoggedIn = "You are now logged in"
englishMessage LoginTitle = "Log In"
englishMessage PleaseProvideUsername = "Please fill in your username"
englishMessage PleaseProvidePassword = "Please fill in your password"
englishMessage NoIdentifierProvided = "No email/username provided"
englishMessage InvalidEmailAddress = "Invalid email address provided"
englishMessage PasswordResetTitle = "Password Reset"
englishMessage ProvideIdentifier = "Email or Username"
englishMessage SendPasswordResetEmail = "Send password reset email"
englishMessage PasswordResetPrompt =
  "Enter your e-mail address or username below, and a password reset e-mail will be sent to you."
englishMessage InvalidUsernamePass = "Invalid username/password combination"
englishMessage (IdentifierNotFound ident) = "Login not found: " `mappend` ident
englishMessage Logout = "Log Out"
englishMessage LogoutTitle = "Log Out"
englishMessage AuthError = "Authentication Error"
englishMessage MalformedJSONMessage = "Malformed Credentials JSON"
englishMessage MissingEmailMessage = "No email provided"
englishMessage MissingPasswordMessage = "No password provided"
englishMessage (AccountNotVerified email) = "Account for user " `mappend` email `mappend` " is not verified"
englishMessage (PasswordNotSet email) = "Password is not set for user " `mappend` email
englishMessage (PasswordMismatch email) =
  "Password given mismatches with password stored in DB for user " `mappend` email
englishMessage (LoginFailureEmail email) = "Login for user " `mappend` email `mappend` " failed"
englishMessage LoginFailure = "Login for user failed"
englishMessage AlreadyRegistered = "This email is already registered"
englishMessage (UserRowNotInValidState email) = "User row " `mappend` email `mappend` " not in valid state"
englishMessage RegistrationFailure = "Registration was unsuccessful due to an internal error"
englishMessage ForgotPasswordFailure = "Forgot Password request was unsuccessful due to an internal error"
englishMessage (ResetPasswordEmailSent email) =
  "A reset password e-mail has been sent to " `mappend` email `mappend` "."
englishMessage (MissingNewPasswordInternalMessage userId) =
  "Request body for /reset-password from user with userId " `mappend` userId `mappend` " did not contain newPassword field"
englishMessage MissingNewPasswordMessage = "No newPassword provided"
englishMessage (MissingConfirmPasswordInternalMessage userId) =
  "Request body for /reset-password from user with userId " `mappend` userId `mappend` " did not contain confirmPassword field"
englishMessage MissingConfirmPasswordMessage = "No confirmPassword provided"
englishMessage (PassMismatchInternalMessage userId) =
  "Request body for /reset-password from user with userId " `mappend` userId `mappend` " contains different newPassword and confirmPassword fields"
englishMessage (InvalidVerificationKeyInternalMessage userId verificationKey storedVerificationKey) =
  "Invalid verification key. User with userId " `mappend` userId `mappend` " requested /set-password with verification key "
  `mappend` verificationKey `mappend` " but stored verification key was " `mappend` storedVerificationKey
englishMessage InvalidVerificationKey = "Invalid verification key"
englishMessage (MissingVerificationKeyInternalMessage userId verificationKey) =
  "Invalid verification key. User with userId " `mappend` userId `mappend` " requested /set-password with verification key "
  `mappend` verificationKey `mappend` " but stored verification key was not set"
englishMessage (UnableToDecryptUserId encryptedUserId) = "Unable to decrypt " `mappend` encryptedUserId
englishMessage (NoSuchUser email) = "No user with email " `mappend` email `mappend` " found"