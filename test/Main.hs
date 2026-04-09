module Main (main) where

import Test.Hspec

import Network.Wai.Handler.WarpS2N (Library (..), withS2nTls)

import AppMonadTests (appMonadSpec)
import CertLoadingTests (certLoadingSpec)
import IntegrationTests (integrationSpec)
import ProtocolTests (protocolSpec)

main :: IO ()
main = hspec $ do
    aroundAll (withS2nTls Linked) $ do
        describe "Certificate Loading" certLoadingSpec
        describe "Integration" integrationSpec
        describe "Protocol" protocolSpec
        describe "AppMonad ergonomics" appMonadSpec
