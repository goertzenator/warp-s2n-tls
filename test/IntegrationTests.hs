{-# LANGUAGE NumericUnderscores #-}

module IntegrationTests (integrationTests) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (replicateConcurrently)
import Control.Exception (SomeException, try)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Network.Connection qualified as Conn
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertFailure, testCase)

import Network.Wai.Handler.WarpS2N (S2nTls, tlsSettings)

import TestUtils

integrationTests :: S2nTls IO -> TestTree
integrationTests tls =
    testGroup
        "Integration"
        [ testBasicTLSRoundtrip tls
        , testMultipleRequests tls
        , testConcurrentConnections tls
        , testLargePayload tls
        ]

-- | Test basic TLS connection and HTTP roundtrip
testBasicTLSRoundtrip :: S2nTls IO -> TestTree
testBasicTLSRoundtrip tls =
    testGroup
        "Basic TLS roundtrip"
        [ testCase "establishes TLS connection and receives response" $ do
            let settings = tlsSettings testCertPath testKeyPath
            withTestServer tls settings $ \port -> do
                result <- makeSecureRequest port
                case result of
                    Left err -> assertFailure $ "Request failed: " ++ err
                    Right response -> do
                        -- Response should contain "OK" and HTTP status
                        let responseStr = LBS.toStrict response
                        assertBool "Response contains HTTP" (BS.isInfixOf "HTTP" responseStr)
                        assertBool "Response contains 200" (BS.isInfixOf "200" responseStr)
                        assertBool "Response contains blarg body" (BS.isInfixOf "blarg" responseStr)
        , testCase "handles connection close gracefully" $ do
            let settings = tlsSettings testCertPath testKeyPath
            withTestServer tls settings $ \port -> do
                -- Make request and ensure it completes
                result <- makeSecureRequest port
                case result of
                    Left err -> assertFailure $ "Request failed: " ++ err
                    Right _ -> pure ()
                -- Server should still be running for another request
                result2 <- makeSecureRequest port
                case result2 of
                    Left err -> assertFailure $ "Second request failed: " ++ err
                    Right _ -> pure ()
        ]

-- | Test multiple sequential requests on same server
testMultipleRequests :: S2nTls IO -> TestTree
testMultipleRequests tls =
    testGroup
        "Multiple requests"
        [ testCase "handles 10 sequential requests" $ do
            let settings = tlsSettings testCertPath testKeyPath
            withTestServer tls settings $ \port -> do
                results <- mapM (\_ -> makeSecureRequest port) [1 .. 10 :: Int]
                let failures = [e | Left e <- results]
                assertBool ("Some requests failed: " ++ show failures) (null failures)
        , testCase "handles requests with small delays" $ do
            let settings = tlsSettings testCertPath testKeyPath
            withTestServer tls settings $ \port -> do
                results <-
                    mapM
                        ( \_ -> do
                            threadDelay 50_000 -- 50ms delay
                            makeSecureRequest port
                        )
                        [1 .. 5 :: Int]
                let failures = [e | Left e <- results]
                assertBool ("Some requests failed: " ++ show failures) (null failures)
        ]

-- | Test concurrent connections
testConcurrentConnections :: S2nTls IO -> TestTree
testConcurrentConnections tls =
    testGroup
        "Concurrent connections"
        [ testCase "handles 10 concurrent connections" $ do
            let settings = tlsSettings testCertPath testKeyPath
            withTestServer tls settings $ \port -> do
                results <- replicateConcurrently 10 (makeSecureRequest port)
                let successes = length [() | Right _ <- results]
                let failures = [e | Left e <- results]
                assertBool
                    ("Only " ++ show successes ++ "/10 succeeded, failures: " ++ show failures)
                    (successes == 10) -- Allow some failures due to timing
        , testCase "handles 100 concurrent connections" $ do
            let settings = tlsSettings testCertPath testKeyPath
            withTestServer tls settings $ \port -> do
                results <- replicateConcurrently 100 (makeSecureRequest port)
                let successes = length [() | Right _ <- results]
                assertBool
                    ("Only " ++ show successes ++ "/100 succeeded")
                    (successes == 100) -- Allow some failures
        ]

-- | Test with larger payloads
testLargePayload :: S2nTls IO -> TestTree
testLargePayload tls =
    testGroup
        "Large payloads"
        [ testCase "client can send larger request" $ do
            let settings = tlsSettings testCertPath testKeyPath
            withTestServer tls settings $ \port -> do
                -- Connect and send a request with a larger body
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

                    -- Send POST with 1MB body
                    let body = BS.replicate 1_000_000 0x41 -- 1MB of 'A's
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

                    -- Read response
                    response <- readAll conn
                    Conn.connectionClose conn
                    pure response

                case result of
                    Left e -> assertFailure $ "Large request failed: " ++ show e
                    Right response ->
                        assertBool "Response received" (BS.length response > 0)
        ]
  where
    readAll conn = do
        chunk <- Conn.connectionGetChunk conn
        if BS.null chunk
            then pure BS.empty
            else do
                rest <- readAll conn
                pure (chunk <> rest)
