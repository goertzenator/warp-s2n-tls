{-# LANGUAGE NumericUnderscores #-}

module ProtocolTests (protocolSpec) where

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
    TLSSettings (..),
    runTLSSocketLib,
    tlsSettings,
 )
import S2nTls (S2nTls (..))
import Test.Hspec (SpecWith, describe, expectationFailure, it, shouldBe)
import TestUtils
import UnliftIO.Async
import UnliftIO.Concurrent
import UnliftIO.STM

protocolSpec :: SpecWith S2nTls
protocolSpec = do
    describe "TLS version negotiation" versionNegotiationSpec
    describe "Cipher preferences" cipherPreferencesSpec

versionNegotiationSpec :: SpecWith S2nTls
versionNegotiationSpec = do
    it "negotiates TLS 1.3 with default settings" $ \tls -> do
        let serverSettings = tlsSettings testCertPath testKeyPath
        negotiatedVersion <- withTestServerGetVersion tls serverSettings [TLS.TLS13, TLS.TLS12]
        case negotiatedVersion of
            Just TLS.TLS13 -> pure ()
            Just v -> expectationFailure $ "Expected TLS 1.3, got " ++ show v
            Nothing -> expectationFailure "Failed to get negotiated version"

    it "negotiates TLS 1.2 when client only supports TLS 1.2" $ \tls -> do
        let serverSettings =
                (tlsSettings testCertPath testKeyPath)
                    { tlsCipherPreferences = "default"
                    }
        negotiatedVersion <- withTestServerGetVersion tls serverSettings [TLS.TLS12]
        case negotiatedVersion of
            Just TLS.TLS12 -> pure ()
            Just v -> expectationFailure $ "Expected TLS 1.2, got " ++ show v
            Nothing -> expectationFailure "Failed to get negotiated version"

    it "fails when no common TLS version" $ \tls -> do
        let serverSettings =
                (tlsSettings testCertPath testKeyPath)
                    { tlsCipherPreferences = "default_tls13"
                    }
        result <-
            try @SomeException $
                withTestServerGetVersion tls serverSettings [TLS.TLS10]
        case result of
            Left _ -> pure ()
            Right (Just v) -> expectationFailure $ "Should have failed but got " ++ show v
            Right Nothing -> pure ()

cipherPreferencesSpec :: SpecWith S2nTls
cipherPreferencesSpec = do
    it "accepts connection with default_tls13 policy" $ \tls -> do
        let serverSettings =
                (tlsSettings testCertPath testKeyPath)
                    { tlsCipherPreferences = "default_tls13"
                    }
        result <- withTestServerConnect tls serverSettings
        result `shouldBe` True

    it "accepts connection with default policy" $ \tls -> do
        let serverSettings =
                (tlsSettings testCertPath testKeyPath)
                    { tlsCipherPreferences = "default"
                    }
        result <- withTestServerConnect tls serverSettings
        result `shouldBe` True

-- | Helper: Start server and get negotiated TLS version from client perspective
withTestServerGetVersion :: S2nTls -> TLSSettings -> [TLS.Version] -> IO (Maybe TLS.Version)
withTestServerGetVersion tls tlsSet clientVersions =
    bracket bindFreePort (Socket.close . fst) $ \(sock, port) -> do
        serverReady <- newEmptyTMVarIO
        let app _ respond = respond $ responseLBS status200 [] "blarg!"
            warpSet = setBeforeMainLoop (atomically $ putTMVar serverReady ()) defaultSettings
        withAsync (runTLSSocketLib tls tlsSet warpSet sock app) $ \as -> do
            atomically $ waitSTM as <|> takeTMVar serverReady
            threadDelay 10_000
            backend <- makeClientSocket port
            params <- makeClientParams clientVersions
            ctx <- TLS.contextNew backend params
            TLS.handshake ctx
            info <- TLS.contextGetInformation ctx
            let version = TLS.infoVersion <$> info
            TLS.bye ctx
            pure version

-- | Helper: Start server and test if connection succeeds
withTestServerConnect :: S2nTls -> TLSSettings -> IO Bool
withTestServerConnect tls tlsSet =
    bracket bindFreePort (Socket.close . fst) $ \(sock, port) -> do
        serverReady <- newEmptyTMVarIO

        let app _ respond = respond $ responseLBS status200 [] "blarg!"
            warpSet = setBeforeMainLoop (atomically $ putTMVar serverReady ()) defaultSettings

        withAsync (runTLSSocketLib tls tlsSet warpSet sock app) $ \as -> do
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
                    { TLS.onServerCertificate = \_ _ _ _ -> pure []
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
