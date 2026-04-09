{-# LANGUAGE NumericUnderscores #-}

module IntegrationTests (integrationSpec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (replicateConcurrently)
import Control.Exception (SomeException, try)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Network.Connection qualified as Conn
import S2nTls (S2nTls (..))
import Test.Hspec (SpecWith, describe, expectationFailure, it, shouldBe, shouldSatisfy)

import Network.Wai.Handler.WarpS2N (tlsSettings)

import TestUtils

integrationSpec :: SpecWith S2nTls
integrationSpec = do
    describe "Basic TLS roundtrip" basicRoundtripSpec
    describe "Multiple requests" multipleRequestsSpec
    describe "Concurrent connections" concurrentSpec
    describe "Large payloads" largePayloadSpec

basicRoundtripSpec :: SpecWith S2nTls
basicRoundtripSpec = do
    it "establishes TLS connection and receives response" $ \tls -> do
        let settings = tlsSettings testCertPath testKeyPath
        withTestServer tls settings $ \port -> do
            result <- makeSecureRequest port
            case result of
                Left err -> expectationFailure $ "Request failed: " ++ err
                Right response -> do
                    let responseStr = LBS.toStrict response
                    responseStr `shouldSatisfy` BS.isInfixOf "HTTP"
                    responseStr `shouldSatisfy` BS.isInfixOf "200"
                    responseStr `shouldSatisfy` BS.isInfixOf "blarg"

    it "handles connection close gracefully" $ \tls -> do
        let settings = tlsSettings testCertPath testKeyPath
        withTestServer tls settings $ \port -> do
            result <- makeSecureRequest port
            case result of
                Left err -> expectationFailure $ "Request failed: " ++ err
                Right _ -> pure ()
            result2 <- makeSecureRequest port
            case result2 of
                Left err -> expectationFailure $ "Second request failed: " ++ err
                Right _ -> pure ()

multipleRequestsSpec :: SpecWith S2nTls
multipleRequestsSpec = do
    it "handles 10 sequential requests" $ \tls -> do
        let settings = tlsSettings testCertPath testKeyPath
        withTestServer tls settings $ \port -> do
            results <- mapM (\_ -> makeSecureRequest port) [1 .. 10 :: Int]
            let failures = [e | Left e <- results]
            failures `shouldBe` []

    it "handles requests with small delays" $ \tls -> do
        let settings = tlsSettings testCertPath testKeyPath
        withTestServer tls settings $ \port -> do
            results <-
                mapM
                    ( \_ -> do
                        threadDelay 50_000
                        makeSecureRequest port
                    )
                    [1 .. 5 :: Int]
            let failures = [e | Left e <- results]
            failures `shouldBe` []

concurrentSpec :: SpecWith S2nTls
concurrentSpec = do
    it "handles 10 concurrent connections" $ \tls -> do
        let settings = tlsSettings testCertPath testKeyPath
        withTestServer tls settings $ \port -> do
            results <- replicateConcurrently 10 (makeSecureRequest port)
            let successes = length [() | Right _ <- results]
            successes `shouldBe` 10

    it "handles 25 concurrent connections" $ \tls -> do
        let settings = tlsSettings testCertPath testKeyPath
        withTestServer tls settings $ \port -> do
            results <- replicateConcurrently 25 (makeSecureRequest port)
            let successes = length [() | Right _ <- results]
            successes `shouldSatisfy` (>= 23)

largePayloadSpec :: SpecWith S2nTls
largePayloadSpec = do
    it "client can send larger request" $ \tls -> do
        let settings = tlsSettings testCertPath testKeyPath
        withTestServer tls settings $ \port -> do
            result <- try @SomeException $ do
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

                let body = BS.replicate 1_000_000 0x41
                    request =
                        BS.concat
                            [ "POST / HTTP/1.1\r\n"
                            , "Host: localhost\r\n"
                            , "Content-Length: 1000000\r\n"
                            , "Connection: close\r\n"
                            , "\r\n"
                            , body
                            ]
                Conn.connectionPut conn request

                response <- readAll conn
                Conn.connectionClose conn
                pure response

            case result of
                Left e -> expectationFailure $ "Large request failed: " ++ show e
                Right response ->
                    BS.length response `shouldSatisfy` (> 0)
  where
    readAll conn = do
        chunk <- Conn.connectionGetChunk conn
        if BS.null chunk
            then pure BS.empty
            else do
                rest <- readAll conn
                pure (chunk <> rest)
