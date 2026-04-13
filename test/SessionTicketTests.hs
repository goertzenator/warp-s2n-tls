{-# LANGUAGE NumericUnderscores #-}

module SessionTicketTests (sessionTicketSpec) where

import Control.Applicative
import Control.Exception (bracket)
import Data.ByteString qualified as BS
import Data.IORef (newIORef, readIORef, writeIORef)
import Network.HTTP.Types (status200)
import Network.Socket qualified as Net
import Network.Wai (Application, responseLBS)
import Network.Wai.Handler.Warp (defaultSettings, setBeforeMainLoop)
import Network.Wai.Handler.WarpS2N (S2nTls, runTLSSocket, tlsSettings)
import S2nTls qualified
import Test.Hspec
import TestUtils (testCertPath, testKeyPath)
import UnliftIO.Async
import UnliftIO.Concurrent
import UnliftIO.STM

-- | Simple application that echoes back the request path
echoApp :: Application
echoApp _req respond = respond $ responseLBS status200 [] "OK"

-- | Run a test server and execute an action with its port
withTicketTestServer :: S2nTls -> (Net.PortNumber -> IO a) -> IO a
withTicketTestServer tls action = do
    -- Create and bind socket
    sock <- Net.socket Net.AF_INET Net.Stream Net.defaultProtocol
    Net.setSocketOption sock Net.ReuseAddr 1
    Net.bind sock (Net.SockAddrInet 0 (Net.tupleToHostAddress (127, 0, 0, 1)))
    Net.listen sock 5
    port <- Net.socketPort sock

    serverReady <- newEmptyTMVarIO
    let warpSet = setBeforeMainLoop (atomically $ putTMVar serverReady ()) defaultSettings
        -- Use default tlsSettings which includes basicTicketKeyManager
        tlsSet = tlsSettings testCertPath testKeyPath

    -- Run server in background
    withAsync (runTLSSocket tls tlsSet warpSet sock echoApp) $ \as -> do
        startupResult <-
            atomically $
                (Left <$> waitCatchSTM as)
                    <|> (Right <$> takeTMVar serverReady)
        case startupResult of
            Right () -> pure ()
            Left e -> do
                Net.close sock
                error $ "Server failed to start: " <> show e

        -- Small delay for server to be fully ready
        threadDelay 50_000

        -- Run the test action
        result <- action port

        -- Cleanup
        Net.close sock
        threadDelay 100_000
        pure result

-- | Connect to the test server
connectToServer :: Net.PortNumber -> IO Net.Socket
connectToServer port = do
    sock <- Net.socket Net.AF_INET Net.Stream Net.defaultProtocol
    let hints = Net.defaultHints{Net.addrSocketType = Net.Stream}
    addr : _ <- Net.getAddrInfo (Just hints) (Just "127.0.0.1") (Just (show port))
    Net.connect sock (Net.addrAddress addr)
    pure sock

sessionTicketSpec :: SpecWith S2nTls
sessionTicketSpec = describe "Session Tickets" $ do
    it "resumes session using ticket from first connection" $ \tls -> do
        -- IORef to store the session ticket
        ticketRef <- newIORef Nothing

        -- Create client config with session ticket callback
        clientConfig <- tls.newConfig
        tls.disableX509Verification clientConfig
        tls.setCipherPreferences clientConfig "default_tls13"
        tls.setSessionTicketsOnOff clientConfig True
        tls.setSessionTicketCallback clientConfig $ \ticketData _lifetime -> do
            writeIORef ticketRef (Just ticketData)

        withTicketTestServer tls $ \port -> do
            -- First connection: establish and get ticket
            bracket (connectToServer port) Net.close $ \sock1 -> do
                conn1 <- tls.newConnection S2nTls.Client
                tls.setConnectionConfig conn1 clientConfig
                tls.setServerName conn1 "localhost"
                tls.setSocket conn1 sock1
                tls.blockingNegotiate conn1

                -- First connection should NOT be resumed
                resumed1 <- tls.isSessionResumed conn1
                resumed1 `shouldBe` False

                -- Send a simple HTTP request
                tls.blockingSendAll conn1 "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

                -- Read response
                response1 <- tls.blockingRecv conn1 4096
                BS.isInfixOf "200 OK" response1 `shouldBe` True

            -- Wait for ticket callback to fire
            threadDelay 200_000

            -- Verify we got a ticket
            mTicket <- readIORef ticketRef
            mTicket `shouldSatisfy` (/= Nothing)

            -- Second connection: use the ticket for resumption
            bracket (connectToServer port) Net.close $ \sock2 -> do
                conn2 <- tls.newConnection S2nTls.Client
                tls.setConnectionConfig conn2 clientConfig
                tls.setServerName conn2 "localhost"

                -- Set the session ticket for resumption
                case mTicket of
                    Just ticket -> tls.setSession conn2 ticket
                    Nothing -> error "No ticket available"

                tls.setSocket conn2 sock2
                tls.blockingNegotiate conn2

                -- Second connection SHOULD be resumed
                resumed2 <- tls.isSessionResumed conn2
                resumed2 `shouldBe` True

                -- Verify connection still works
                tls.blockingSendAll conn2 "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                response2 <- tls.blockingRecv conn2 4096
                BS.isInfixOf "200 OK" response2 `shouldBe` True
