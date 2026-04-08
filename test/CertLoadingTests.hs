module CertLoadingTests (certLoadingTests) where

import Control.Exception (SomeException, try)
import Data.ByteString qualified as BS
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertFailure, testCase)

import Network.Wai.Handler.WarpS2N (
    CertSettings (..),
    S2nTls,
    TLSSettings (..),
    defaultTlsSettings,
    tlsSettings,
    tlsSettingsChain,
    tlsSettingsChainMemory,
    tlsSettingsMemory,
 )

import TestUtils

certLoadingTests :: S2nTls IO -> TestTree
certLoadingTests tls =
    testGroup
        "Certificate Loading"
        [ testSmartConstructors
        , testFileLoading tls
        , testMemoryLoading tls
        , testInvalidCerts tls
        ]

-- | Test that smart constructors create correct CertSettings
testSmartConstructors :: TestTree
testSmartConstructors =
    testGroup
        "Smart constructors"
        [ testCase "tlsSettings creates CertFromFile with empty chain" $ do
            let settings = tlsSettings "cert.pem" "key.pem"
            case tlsCertSettings settings of
                CertFromFile cert chain key -> do
                    assertBool "cert path" (cert == "cert.pem")
                    assertBool "empty chain" (null chain)
                    assertBool "key path" (key == "key.pem")
                _ -> assertFailure "Expected CertFromFile"
        , testCase "tlsSettingsChain includes chain files" $ do
            let settings = tlsSettingsChain "cert.pem" ["inter1.pem", "inter2.pem"] "key.pem"
            case tlsCertSettings settings of
                CertFromFile cert chain key -> do
                    assertBool "cert path" (cert == "cert.pem")
                    assertBool "chain files" (chain == ["inter1.pem", "inter2.pem"])
                    assertBool "key path" (key == "key.pem")
                _ -> assertFailure "Expected CertFromFile"
        , testCase "tlsSettingsMemory creates CertFromMemory" $ do
            let settings = tlsSettingsMemory "CERT" "KEY"
            case tlsCertSettings settings of
                CertFromMemory cert chain key -> do
                    assertBool "cert data" (cert == "CERT")
                    assertBool "empty chain" (null chain)
                    assertBool "key data" (key == "KEY")
                _ -> assertFailure "Expected CertFromMemory"
        , testCase "tlsSettingsChainMemory includes chain data" $ do
            let settings = tlsSettingsChainMemory "CERT" ["INTER1", "INTER2"] "KEY"
            case tlsCertSettings settings of
                CertFromMemory cert chain key -> do
                    assertBool "cert data" (cert == "CERT")
                    assertBool "chain data" (chain == ["INTER1", "INTER2"])
                    assertBool "key data" (key == "KEY")
                _ -> assertFailure "Expected CertFromMemory"
        , testCase "defaultTlsSettings has expected defaults" $ do
            let settings = defaultTlsSettings
            assertBool "cipher prefs" (tlsCipherPreferences settings == "default_tls13")
            case tlsCertSettings settings of
                CertFromFile cert _ key -> do
                    assertBool "default cert" (cert == "certificate.pem")
                    assertBool "default key" (key == "key.pem")
                _ -> assertFailure "Expected CertFromFile"
        ]

-- | Test loading certificates from files
testFileLoading :: S2nTls IO -> TestTree
testFileLoading tls =
    testGroup
        "File loading"
        [ testCase "loads valid cert and key from files" $ do
            let settings = tlsSettings testCertPath testKeyPath
            result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
            case result of
                Left e -> assertFailure $ "Server failed to start: " ++ show e
                Right () -> pure ()
        , testCase "loads cert with empty chain" $ do
            let settings = tlsSettingsChain testCertPath [] testKeyPath
            result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
            case result of
                Left e -> assertFailure $ "Server failed to start: " ++ show e
                Right () -> pure ()
        ]

-- | Test loading certificates from memory
testMemoryLoading :: S2nTls IO -> TestTree
testMemoryLoading tls =
    testGroup
        "Memory loading"
        [ testCase "loads valid cert and key from memory" $ do
            cert <- loadTestCert
            key <- loadTestKey
            let settings = tlsSettingsMemory cert key
            result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
            case result of
                Left e -> assertFailure $ "Server failed to start: " ++ show e
                Right () -> pure ()
        , testCase "loads cert with empty chain from memory" $ do
            cert <- loadTestCert
            key <- loadTestKey
            let settings = tlsSettingsChainMemory cert [] key
            result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
            case result of
                Left e -> assertFailure $ "Server failed to start: " ++ show e
                Right () -> pure ()
        ]

-- | Test behavior with invalid certificates
testInvalidCerts :: S2nTls IO -> TestTree
testInvalidCerts tls =
    testGroup
        "Invalid certificates"
        [ testCase "fails with nonexistent cert file" $ do
            let settings = tlsSettings "nonexistent-cert.pem" testKeyPath
            result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
            case result of
                Left _ -> pure () -- Expected to fail
                Right () -> assertFailure "Should have failed with nonexistent cert"
        , testCase "fails with nonexistent key file" $ do
            let settings = tlsSettings testCertPath "nonexistent-key.pem"
            result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
            case result of
                Left _ -> pure () -- Expected to fail
                Right () -> assertFailure "Should have failed with nonexistent key"
        , testCase "fails with invalid PEM data" $ do
            let settings = tlsSettingsMemory "not a valid cert" "not a valid key"
            result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
            case result of
                Left _ -> pure () -- Expected to fail
                Right () -> assertFailure "Should have failed with invalid PEM"
        , testCase "fails with empty cert" $ do
            let settings = tlsSettingsMemory BS.empty BS.empty
            result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
            case result of
                Left _ -> pure () -- Expected to fail
                Right () -> assertFailure "Should have failed with empty cert"
        , testCase "fails with mismatched cert and key" $ do
            cert <- loadTestCert
            let fakeKey = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7\n-----END PRIVATE KEY-----\n"
            let settings = tlsSettingsMemory cert fakeKey
            result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
            case result of
                Left _ -> pure () -- Expected to fail
                Right () -> assertFailure "Should have failed with mismatched key"
        ]
