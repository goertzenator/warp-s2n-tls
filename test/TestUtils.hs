{-# LANGUAGE NumericUnderscores #-}

module TestUtils (
    withTestServer,
    makeSecureRequest,
    testCertPath,
    testKeyPath,
    loadTestCert,
    loadTestKey,
) where

-- import Control.Concurrent (threadDelay)
-- import Control.Concurrent.Async (race, withAsync)
-- import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)

import Control.Applicative
import Control.Exception (SomeException, try)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Network.Connection qualified as Conn
import Network.HTTP.Types (status200)
import Network.Socket
import Network.Wai (Application, responseLBS)
import Network.Wai.Handler.Warp (Port, defaultSettings, setBeforeMainLoop)
import Network.Wai.Handler.WarpS2N (S2nTls, TLSSettings, runTLSSocket)
import UnliftIO.Async
import UnliftIO.Concurrent
import UnliftIO.STM

-- | Path to test server certificate
testCertPath :: FilePath
testCertPath = "test/certs/server.pem"

-- | Path to test server key
testKeyPath :: FilePath
testKeyPath = "test/certs/server-key.pem"

-- | Load test certificate as ByteString
loadTestCert :: IO ByteString
loadTestCert = BS.readFile testCertPath

-- | Load test key as ByteString
loadTestKey :: IO ByteString
loadTestKey = BS.readFile testKeyPath

-- | Simple echo application for testing
echoApp :: Application
echoApp _req respond = respond $ responseLBS status200 [] "blarg!"

-- | Run a test server and execute an action with its port.
withTestServer :: S2nTls IO -> TLSSettings -> (Port -> IO a) -> IO a
withTestServer tls tlsSet action = do
    -- Create and bind socket
    sock <- socket AF_INET Stream defaultProtocol
    setSocketOption sock ReuseAddr 1
    bind sock (SockAddrInet 0 (tupleToHostAddress (127, 0, 0, 1)))
    listen sock 5
    port <- fromIntegral <$> socketPort sock

    serverReady <- newEmptyTMVarIO
    let warpSet = setBeforeMainLoop (atomically $ putTMVar serverReady ()) defaultSettings

    -- Run server in background, execute action, then cleanup
    withAsync (runTLSSocket tls tlsSet warpSet sock echoApp) $ \as -> do
        startupResult <-
            atomically $
                (Left <$> waitCatchSTM as)
                    <|> (Right <$> takeTMVar serverReady)
        case startupResult of
            Right () -> pure ()
            Left e -> do
                close sock
                error $ "Server failed to start: " <> show e

        -- Small additional delay for server to be fully ready
        threadDelay 50_000

        -- Run the test action
        result <- action port

        -- Cleanup
        close sock
        threadDelay 100_000 -- 100ms cleanup delay
        pure result

-- | Make a secure HTTPS request to localhost, returning response body.
makeSecureRequest :: Port -> IO (Either String LBS.ByteString)
makeSecureRequest port = do
    result <- try @SomeException $ do
        -- Connect with TLS
        ctx <- Conn.initConnectionContext
        conn <-
            Conn.connectTo
                ctx
                Conn.ConnectionParams
                    { Conn.connectionHostname = "localhost"
                    , Conn.connectionPort = fromIntegral port
                    , Conn.connectionUseSecure =
                        Just
                            Conn.TLSSettingsSimple
                                { Conn.settingDisableCertificateValidation = True
                                , Conn.settingDisableSession = False
                                , Conn.settingUseServerName = True
                                }
                    , Conn.connectionUseSocks = Nothing
                    }

        -- Send HTTP request
        Conn.connectionPut conn "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        -- Read response with timeout
        response <- readAllWithTimeout conn 5_000_000
        Conn.connectionClose conn
        pure $ LBS.fromStrict response

    pure $ case result of
        Left e -> Left (show e)
        Right bs -> Right bs

-- | Read all data from connection with a timeout
readAllWithTimeout :: Conn.Connection -> Int -> IO ByteString
readAllWithTimeout conn timeoutMicros = do
    result <- race (threadDelay timeoutMicros) (readAll conn)
    case result of
        Left () -> pure BS.empty -- Timeout, return what we have
        Right bs -> pure bs
  where
    readAll c = do
        chunk <- Conn.connectionGetChunk c
        if BS.null chunk
            then pure BS.empty
            else do
                rest <- readAll c
                pure (chunk <> rest)
