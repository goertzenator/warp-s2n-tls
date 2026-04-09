{-# LANGUAGE NumericUnderscores #-}

module AppMonadTests (appMonadSpec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (race_)
import Control.Monad.Reader (ReaderT, ask, runReaderT)
import Data.ByteString.Lazy.Char8 qualified as LBS8
import Network.HTTP.Types (status200)
import Network.Wai (Application, responseLBS)
import Network.Wai.Handler.Warp (defaultSettings)
import S2nTls (S2nTls (..))
import Test.Hspec (SpecWith, it)
import UnliftIO (MonadIO (..), withRunInIO)

import Network.Wai.Handler.WarpS2N (runTLS, tlsSettings)

import TestUtils (testCertPath, testKeyPath)

-- | Dummy environment for testing MonadUnliftIO ergonomics
data Env = Env
    { envName :: String
    , envTls :: S2nTls
    }

-- | Our application monad
type AppM = ReaderT Env IO

-- | Run a brief server in AppM to test API ergonomics
runBriefServer :: AppM ()
runBriefServer = do
    env <- ask
    liftIO $ putStrLn $ "Starting server with env: " ++ envName env

    let tlsSet = tlsSettings testCertPath testKeyPath

    -- AppM Application pattern - demonstrates creating a WAI Application
    -- that can access the ReaderT environment
    let mkApp :: AppM Application
        mkApp = withRunInIO $ \runInIO -> pure $ \_request respond -> do
            Env{envName} <- runInIO ask
            respond $ responseLBS status200 [] (LBS8.pack envName)
    app <- mkApp

    -- Run server for 2 seconds then kill it
    -- Server runs in IO, but we're orchestrating from AppM
    liftIO $
        race_
            (threadDelay 2_000_000)
            (runTLS (envTls env) tlsSet defaultSettings app)

    liftIO $ putStrLn "Server stopped"

-- | Test that the API works ergonomically with a custom monad stack
appMonadSpec :: SpecWith S2nTls
appMonadSpec = do
    it "runs server in ReaderT Env IO" $ \tls -> do
        let env = Env{envName = "test-env", envTls = tls}
        runReaderT runBriefServer env
