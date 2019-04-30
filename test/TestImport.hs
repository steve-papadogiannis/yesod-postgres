{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
module TestImport
    ( module TestImport
    , module X
    ) where

import Application           (makeFoundation, makeLogWare)
import ClassyPrelude         as X hiding (delete, deleteBy, Handler)
import Database.Persist      as X hiding (get)
import Database.Persist.Sql  (SqlPersistM, runSqlPersistMPool, rawExecute, rawSql, unSingle, connEscapeName)
import Foundation            as X
import Model                 as X
import Test.Hspec            as X
import Text.Shakespeare.Text (st)
import Yesod.Default.Config2 (useEnv, loadYamlSettings)
import Custom.Auth           as X
import Custom.Auth.Routes    as X
import Yesod.Test            as X
import Yesod.Core.Unsafe     (fakeHandlerGetLogger)
import Data.Maybe            (fromJust)
import Data.Aeson            as X
import Data.CaseInsensitive (CI)
import qualified Data.ByteString.Char8 as BS8
import Network.Wai.Test hiding (assertHeader, assertNoHeader, request)
import qualified Data.Text as T
import qualified Test.HUnit as HUnit

runDB :: SqlPersistM a -> YesodExample App a
runDB query = do
    app <- getTestYesod
    liftIO $ runDBWithApp app query

runDBWithApp :: App -> SqlPersistM a -> IO a
runDBWithApp app query = runSqlPersistMPool query (appConnPool app)

runHandler :: Handler a -> YesodExample App a
runHandler handler = do
    app <- getTestYesod
    fakeHandlerGetLogger appLogger app handler


withApp :: SpecWith (TestApp App) -> Spec
withApp = before $ do
    settings <- loadYamlSettings
        ["config/test-settings.yml", "config/settings.yml"]
        []
        useEnv
    foundation <- makeFoundation settings
    wipeDB foundation
    logWare <- liftIO $ makeLogWare foundation
    return (foundation, logWare)

-- This function will truncate all of the tables in your database.
-- 'withApp' calls it before each test, creating a clean environment for each
-- spec to run in.
wipeDB :: App -> IO ()
wipeDB app = runDBWithApp app $ do
    tables <- getTables
    sqlBackend <- ask

    let escapedTables = map (connEscapeName sqlBackend . DBName) tables
        query = "TRUNCATE TABLE " ++ intercalate ", " escapedTables
    rawExecute query []

getTables :: DB [Text]
getTables = do
    tables <- rawSql [st|
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public';
    |] []

    return $ map unSingle tables

-- | Authenticate as a user. This relies on the `auth-dummy-login: true` flag
-- being set in test-settings.yaml, which enables dummy authentication in
-- Foundation.hs
authenticateAs :: Entity User -> YesodExample App ()
authenticateAs (Entity _ u) = do
    let email = userEmail u
        body = object [ "email" .= email,
                        "password" .= ("kurwa" :: Text)]
        encoded = encode body

    request $ do
        setMethod "POST"
        setUrl $ AuthR $ PluginR "email" ["login"]
        setRequestBody encoded
        addRequestHeader ("Content-Type", "application/json")



-- | Create a user.  The dummy email entry helps to confirm that foreign-key
-- checking is switched off in wipeDB for those database backends which need it.
createUser :: Text -> YesodExample App (Entity User)
createUser ident =
    runDB $ do
      user <- insertEntity User
          { userEmail = ident
          , userPassword = Just "sha256|16|FnW1y47QCWc85WzoClsjjA==|m5TunH54L9eFCYJyz5UIeVv50E8Uv5+ld3fL3Amev1E="
          , userVerified = True
          , userVerkey = Just ("a" :: Text)
          }
      _ <- insert Email
          { emailEmail = ident
          , emailUserId = Just $ entityKey user
          , emailVerkey = Nothing
          }
      return user

-- | Assert the given header was returned.
assertHeaderWithoutValue :: HasCallStack => CI BS8.ByteString -> YesodExample site ()
assertHeaderWithoutValue header = withResponse $ \ SResponse { simpleHeaders = h } ->
  case lookup header h of
    Nothing -> failure $ T.pack $ concat
        [ "Expected header "
        , show header
        , ", but it was not present"
        ]
    Just value -> return ()

-- Yes, just a shortcut
failure :: (MonadIO a) => T.Text -> a b
failure reason = (liftIO $ HUnit.assertFailure $ T.unpack reason) >> error ""