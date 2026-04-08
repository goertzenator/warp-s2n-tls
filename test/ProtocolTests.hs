{-# LANGUAGE NumericUnderscores #-}

module ProtocolTests (protocolTests) where

import Control.Applicative
import Control.Exception (SomeException, bracket, try)
import Data.Default.Class (def)
import Network.HTTP.Types (status200)
import Network.Socket qualified as Socket
import Network.Socket.ByteString qualified as SocketBS
import Network.TLS qualified as TLS
import Network.TLS.Extra.Cipher qualified as TLS
import Network.Wai (responseLBS)
import Network.Wai.Handler.Warp (defaultSettings, setBeforeMainLoop)
import Network.Wai.Handler.WarpS2N (
    S2nTls,
    TLSSettings (..),
    runTLSSocket,
    tlsSettings,
 )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertFailure, testCase)
import TestUtils
import UnliftIO.Async
import UnliftIO.Concurrent
import UnliftIO.STM

protocolTests :: S2nTls IO -> TestTree
protocolTests tls =
    testGroup
        "Protocol"
        [ testTLSVersionNegotiation tls
        , testCipherPreferences tls
        ]

-- | Test TLS version negotiation
testTLSVersionNegotiation :: S2nTls IO -> TestTree
testTLSVersionNegotiation tls =
    testGroup
        "TLS version negotiation"
        [ testCase "negotiates TLS 1.3 with default settings" $ do
            let serverSettings = tlsSettings testCertPath testKeyPath
            negotiatedVersion <- withTestServerGetVersion tls serverSettings [TLS.TLS13, TLS.TLS12]
            case negotiatedVersion of
                Just TLS.TLS13 -> pure ()
                Just v -> assertFailure $ "Expected TLS 1.3, got " ++ show v
                Nothing -> assertFailure "Failed to get negotiated version"
        , testCase "negotiates TLS 1.2 when client only supports TLS 1.2" $ do
            -- Use a cipher policy that supports TLS 1.2
            let serverSettings =
                    (tlsSettings testCertPath testKeyPath)
                        { tlsCipherPreferences = "default" -- supports TLS 1.2
                        }
            negotiatedVersion <- withTestServerGetVersion tls serverSettings [TLS.TLS12]
            case negotiatedVersion of
                Just TLS.TLS12 -> pure ()
                Just v -> assertFailure $ "Expected TLS 1.2, got " ++ show v
                Nothing -> assertFailure "Failed to get negotiated version"
        , testCase "fails when no common TLS version" $ do
            -- Server only supports TLS 1.3, client only TLS 1.0
            let serverSettings =
                    (tlsSettings testCertPath testKeyPath)
                        { tlsCipherPreferences = "default_tls13"
                        }
            result <-
                try @SomeException $
                    withTestServerGetVersion tls serverSettings [TLS.TLS10]
            case result of
                Left _ -> pure () -- Expected to fail
                Right (Just v) -> assertFailure $ "Should have failed but got " ++ show v
                Right Nothing -> pure () -- Connection failed as expected
        ]

-- | Test cipher preference configurations
testCipherPreferences :: S2nTls IO -> TestTree
testCipherPreferences tls =
    testGroup
        "Cipher preferences"
        [ testCase "accepts connection with default_tls13 policy" $ do
            let serverSettings =
                    (tlsSettings testCertPath testKeyPath)
                        { tlsCipherPreferences = "default_tls13"
                        }
            result <- withTestServerConnect tls serverSettings
            assertBool "Connection should succeed" result
        , testCase "accepts connection with default policy" $ do
            let serverSettings =
                    (tlsSettings testCertPath testKeyPath)
                        { tlsCipherPreferences = "default"
                        }
            result <- withTestServerConnect tls serverSettings
            assertBool "Connection should succeed" result

            -- Note: Testing specific cipher selection would require more complex setup
            -- to query the negotiated cipher from both sides
        ]

-- | Helper: Start server and get negotiated TLS version from client perspective
withTestServerGetVersion :: S2nTls IO -> TLSSettings -> [TLS.Version] -> IO (Maybe TLS.Version)
withTestServerGetVersion tls tlsSet clientVersions =
    bracket bindFreePort (Socket.close . fst) $ \(sock, port) -> do
        serverReady <- newEmptyTMVarIO

        let app _ respond = respond $ responseLBS status200 [] "blarg!"
            warpSet = setBeforeMainLoop (atomically $ putTMVar serverReady ()) defaultSettings

        withAsync (runTLSSocket tls tlsSet warpSet sock app) $ \as -> do
            atomically $ waitSTM as <|> takeTMVar serverReady

            -- atomically $ takeTMVar serverReady
            threadDelay 10_000

            -- Connect with TLS client and capture negotiated version
            backend <- makeClientSocket port
            params <- makeClientParams clientVersions
            ctx <- TLS.contextNew backend params
            TLS.handshake ctx
            info <- TLS.contextGetInformation ctx
            let version = TLS.infoVersion <$> info
            TLS.bye ctx
            pure version

-- | Helper: Start server and test if connection succeeds
withTestServerConnect :: S2nTls IO -> TLSSettings -> IO Bool
withTestServerConnect tls tlsSet =
    bracket bindFreePort (Socket.close . fst) $ \(sock, port) -> do
        serverReady <- newEmptyTMVarIO

        let app _ respond = respond $ responseLBS status200 [] "blarg!"
            warpSet = setBeforeMainLoop (atomically $ putTMVar serverReady ()) defaultSettings

        withAsync (runTLSSocket tls tlsSet warpSet sock app) $ \as -> do
            atomically $ waitSTM as <|> takeTMVar serverReady
            threadDelay 10_000

            result <- try @SomeException $ do
                backend <- makeClientSocket port
                params <- makeClientParams [TLS.TLS13, TLS.TLS12]
                ctx <- TLS.contextNew backend params
                TLS.handshake ctx
                TLS.sendData ctx "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                _ <- TLS.recvData ctx
                TLS.bye ctx

            pure $ case result of
                Left _ -> False
                Right _ -> True

-- | Create client TLS parameters
makeClientParams :: [TLS.Version] -> IO TLS.ClientParams
makeClientParams versions = do
    pure $
        (TLS.defaultParamsClient "localhost" "")
            { TLS.clientSupported =
                def
                    { TLS.supportedCiphers = TLS.ciphersuite_strong
                    , TLS.supportedVersions = versions
                    }
            , TLS.clientShared = def
            , TLS.clientHooks =
                def
                    { TLS.onServerCertificate = \_ _ _ _ -> pure [] -- Skip validation for self-signed
                    }
            }

-- | Create a client socket connected to localhost:port
makeClientSocket :: Int -> IO TLS.Backend
makeClientSocket port = do
    sock <- Socket.socket Socket.AF_INET Socket.Stream Socket.defaultProtocol
    Socket.connect sock (Socket.SockAddrInet (fromIntegral port) (Socket.tupleToHostAddress (127, 0, 0, 1)))
    pure $
        TLS.Backend
            { TLS.backendFlush = pure ()
            , TLS.backendClose = Socket.close sock
            , TLS.backendSend = SocketBS.sendAll sock
            , TLS.backendRecv = SocketBS.recv sock
            }

-- | Bind to a free port
bindFreePort :: IO (Socket.Socket, Int)
bindFreePort = do
    sock <- Socket.socket Socket.AF_INET Socket.Stream Socket.defaultProtocol
    Socket.setSocketOption sock Socket.ReuseAddr 1
    Socket.bind sock (Socket.SockAddrInet 0 (Socket.tupleToHostAddress (127, 0, 0, 1)))
    Socket.listen sock 5
    port <- Socket.socketPort sock
    pure (sock, fromIntegral port)
