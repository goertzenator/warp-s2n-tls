module CertLoadingTests (certLoadingSpec) where

import Control.Exception (SomeException, try)
import Data.ByteString qualified as BS
import S2nTls (S2nTls (..))
import Test.Hspec (SpecWith, describe, expectationFailure, it, shouldBe, shouldSatisfy)

import Network.Wai.Handler.WarpS2N (
    CertSettings (..),
    TLSSettings (..),
    defaultTlsSettings,
    tlsSettings,
    tlsSettingsChain,
    tlsSettingsChainMemory,
    tlsSettingsMemory,
 )

import TestUtils

certLoadingSpec :: SpecWith S2nTls
certLoadingSpec = do
    describe "Smart constructors" smartConstructorsSpec
    describe "File loading" fileLoadingSpec
    describe "Memory loading" memoryLoadingSpec
    describe "Invalid certificates" invalidCertsSpec

smartConstructorsSpec :: SpecWith S2nTls
smartConstructorsSpec = do
    it "tlsSettings creates CertFromFile with empty chain" $ \_ -> do
        let settings = tlsSettings "cert.pem" "key.pem"
        case tlsCertSettings settings of
            CertFromFile cert chain key -> do
                cert `shouldBe` "cert.pem"
                chain `shouldBe` []
                key `shouldBe` "key.pem"
            _ -> expectationFailure "Expected CertFromFile"

    it "tlsSettingsChain includes chain files" $ \_ -> do
        let settings = tlsSettingsChain "cert.pem" ["inter1.pem", "inter2.pem"] "key.pem"
        case tlsCertSettings settings of
            CertFromFile cert chain key -> do
                cert `shouldBe` "cert.pem"
                chain `shouldBe` ["inter1.pem", "inter2.pem"]
                key `shouldBe` "key.pem"
            _ -> expectationFailure "Expected CertFromFile"

    it "tlsSettingsMemory creates CertFromMemory" $ \_ -> do
        let settings = tlsSettingsMemory "CERT" "KEY"
        case tlsCertSettings settings of
            CertFromMemory cert chain key -> do
                cert `shouldBe` "CERT"
                chain `shouldBe` []
                key `shouldBe` "KEY"
            _ -> expectationFailure "Expected CertFromMemory"

    it "tlsSettingsChainMemory includes chain data" $ \_ -> do
        let settings = tlsSettingsChainMemory "CERT" ["INTER1", "INTER2"] "KEY"
        case tlsCertSettings settings of
            CertFromMemory cert chain key -> do
                cert `shouldBe` "CERT"
                chain `shouldBe` ["INTER1", "INTER2"]
                key `shouldBe` "KEY"
            _ -> expectationFailure "Expected CertFromMemory"

    it "defaultTlsSettings has expected defaults" $ \_ -> do
        let settings = defaultTlsSettings
        tlsCipherPreferences settings `shouldBe` "default_tls13"
        case tlsCertSettings settings of
            CertFromFile cert _ key -> do
                cert `shouldBe` "certificate.pem"
                key `shouldBe` "key.pem"
            _ -> expectationFailure "Expected CertFromFile"

fileLoadingSpec :: SpecWith S2nTls
fileLoadingSpec = do
    it "loads valid cert and key from files" $ \tls -> do
        let settings = tlsSettings testCertPath testKeyPath
        result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
        result `shouldSatisfy` isRight

    it "loads cert with empty chain" $ \tls -> do
        let settings = tlsSettingsChain testCertPath [] testKeyPath
        result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
        result `shouldSatisfy` isRight

memoryLoadingSpec :: SpecWith S2nTls
memoryLoadingSpec = do
    it "loads valid cert and key from memory" $ \tls -> do
        cert <- loadTestCert
        key <- loadTestKey
        let settings = tlsSettingsMemory cert key
        result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
        result `shouldSatisfy` isRight

    it "loads cert with empty chain from memory" $ \tls -> do
        cert <- loadTestCert
        key <- loadTestKey
        let settings = tlsSettingsChainMemory cert [] key
        result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
        result `shouldSatisfy` isRight

invalidCertsSpec :: SpecWith S2nTls
invalidCertsSpec = do
    it "fails with nonexistent cert file" $ \tls -> do
        let settings = tlsSettings "nonexistent-cert.pem" testKeyPath
        result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
        result `shouldSatisfy` isLeft

    it "fails with nonexistent key file" $ \tls -> do
        let settings = tlsSettings testCertPath "nonexistent-key.pem"
        result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
        result `shouldSatisfy` isLeft

    it "fails with invalid PEM data" $ \tls -> do
        let settings = tlsSettingsMemory "not a valid cert" "not a valid key"
        result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
        result `shouldSatisfy` isLeft

    it "fails with empty cert" $ \tls -> do
        let settings = tlsSettingsMemory BS.empty BS.empty
        result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
        result `shouldSatisfy` isLeft

    it "fails with mismatched cert and key" $ \tls -> do
        cert <- loadTestCert
        let fakeKey = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7\n-----END PRIVATE KEY-----\n"
        let settings = tlsSettingsMemory cert fakeKey
        result <- try @SomeException $ withTestServer tls settings $ \_ -> pure ()
        result `shouldSatisfy` isLeft

-- Helpers
isRight :: Either a b -> Bool
isRight (Right _) = True
isRight _ = False

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _ = False
