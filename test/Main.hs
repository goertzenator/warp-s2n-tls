module Main (main) where

import Test.Tasty (defaultMain, testGroup)

import Network.Wai.Handler.WarpS2N (withS2n)

import CertLoadingTests (certLoadingTests)
import IntegrationTests (integrationTests)
import ProtocolTests (protocolTests)

main :: IO ()
main = withS2n $ \tls ->
    defaultMain $
        testGroup
            "warp-s2n-tls"
            [ certLoadingTests tls
            , integrationTests tls
            , protocolTests tls
            ]
