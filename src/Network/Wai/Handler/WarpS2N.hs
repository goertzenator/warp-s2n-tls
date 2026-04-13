{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

{- |
Module      : Network.Wai.Handler.WarpS2N
Copyright   : (c) 2026
License     : BSD-3-Clause
Maintainer  : your.email@example.com
Stability   : experimental
Portability : non-portable

TLS support for Warp via s2n-tls.

This module provides an alternative to @warp-tls@ using AWS's s2n-tls
library for TLS termination.

Basic usage:

@
import Network.Wai.Handler.WarpS2N
import Network.Wai.Handler.Warp (defaultSettings, setPort)

main :: IO ()
main = withS2nTls Linked $ \\tls -> do
    let tlsSet = tlsSettings "cert.pem" "key.pem"
        warpSet = setPort 443 defaultSettings
    runTLS tls tlsSet warpSet myApp
@

For dynamic library loading:

@
main = withS2nTls (Dynamic "/path/to/libs2n.so") $ \\tls -> do
    runTLS tls tlsSet warpSet myApp
@
-}
module Network.Wai.Handler.WarpS2N (
  -- * Running TLS
  runTLS,
  runTLSSocket,

  -- * s2n Initialization (re-exported from s2n-tls)
  withS2nTls,
  S2nTls,
  Library (..),

  -- * Settings
  TLSSettings (..),
  defaultTlsSettings,

  -- * Certificate Settings
  CertSettings (..),

  -- * Smart Constructors
  tlsSettings,
  tlsSettingsChain,
  tlsSettingsMemory,
  tlsSettingsChainMemory,

  -- * Session Tickets
  TicketKeyOps (..),
  basicTicketKeyManager,

  -- * Re-exports from s2n-tls
  CertAuthType (CertAuthType),
  pattern CertAuthNone,
  pattern CertAuthOptional,
  pattern CertAuthRequired,
) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (withAsync)
import Control.Exception (bracket, catch, onException)
import Control.Monad (void)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BS8
import Data.IORef (IORef, newIORef, readIORef)
import Data.Streaming.Network (bindPortTCP)
import Data.Word
import Network.Socket (SockAddr, Socket)
import Network.Socket qualified as Socket
import Network.Wai (Application)
import Network.Wai.Handler.Warp (Settings)
import Network.Wai.Handler.Warp qualified as Warp
import Network.Wai.Handler.Warp.Internal qualified as WarpI
import S2nTls
import S2nTls qualified as S2N
import System.Entropy (getEntropy)
import System.IO (IOMode (..), SeekMode (..), hSeek, withBinaryFile)

--------------------------------------------------------------------------------
-- Types
--------------------------------------------------------------------------------

-- | Certificate configuration for TLS.
data CertSettings
  = -- | Load certificate, chain certificates, and key from files.
    -- @CertFromFile certFile chainFiles keyFile@
    CertFromFile !FilePath ![FilePath] !FilePath
  | -- | Use in-memory PEM ByteStrings.
    -- @CertFromMemory certPem chainPems keyPem@
    CertFromMemory !ByteString ![ByteString] !ByteString
  | -- | Dynamic certificates via IORefs for runtime updates/rotation.
    -- @CertFromRef certRef chainRefs keyRef@
    CertFromRef !(IORef ByteString) ![IORef ByteString] !(IORef ByteString)

{- | Operations available to a ticket key manager.

This record provides an abstraction over the underlying TLS library,
allowing key managers to configure ticket encryption without depending
on s2n-tls internals.
-}
data TicketKeyOps = TicketKeyOps
  { setEncryptLifetime :: Word64 -> IO ()
  -- ^ Set the lifetime (in seconds) for which a key can encrypt new tickets.
  -- After this time, the key will only be used for decryption.
  , setDecryptLifetime :: Word64 -> IO ()
  -- ^ Set the lifetime (in seconds) for which a key can decrypt tickets
  -- after it can no longer encrypt. Total key validity is encrypt + decrypt lifetime.
  , addTicketKey :: ByteString -> ByteString -> IO ()
  -- ^ Add a ticket encryption key. Arguments: key name (unique identifier),
  -- key data (should be 32 bytes of cryptographically random data).
  -- The key becomes valid immediately.
  }

{- | Ticket key manager callback type.

The callback receives 'TicketKeyOps' and should:

1. Set up initial ticket encryption keys (runs before server accepts connections)
2. Return an action to be run in an async that rotates keys over time

The separation allows initialization to complete before the server starts
accepting connections, while key rotation continues in the background.
-}
type TicketKeyManager = TicketKeyOps -> IO (IO ())

-- | TLS settings for the server.
data TLSSettings = TLSSettings
  { tlsCertSettings :: !CertSettings
  -- ^ Certificate configuration (cert, chain, key).
  , tlsCipherPreferences :: !String
  -- ^ s2n cipher policy name (e.g., "default_tls13", "default").
  -- See s2n documentation for available policies.
  , tlsWantClientCert :: !CertAuthType
  -- ^ Client certificate authentication type.
  , tlsTicketKeyManager :: !(Maybe TicketKeyManager)
  -- ^ Optional ticket key manager for session resumption via tickets.
  -- When present, session tickets are automatically enabled.
  }

{- | Default TLS settings.

* Loads certificate from @certificate.pem@ and key from @key.pem@
* Uses @default_tls13@ cipher policy
* No client certificate authentication
* Uses 'basicTicketKeyManager' for session ticket support
-}
defaultTlsSettings :: TLSSettings
defaultTlsSettings =
  TLSSettings
    { tlsCertSettings = CertFromFile "certificate.pem" [] "key.pem"
    , tlsCipherPreferences = "default_tls13"
    , tlsWantClientCert = CertAuthNone
    , tlsTicketKeyManager = Just basicTicketKeyManager
    }

--------------------------------------------------------------------------------
-- Smart Constructors
--------------------------------------------------------------------------------

-- | Create TLS settings from certificate and key files.
tlsSettings ::
  -- | Certificate file
  FilePath ->
  -- | Key file
  FilePath ->
  TLSSettings
tlsSettings cert key =
  defaultTlsSettings
    { tlsCertSettings = CertFromFile cert [] key
    }

-- | Create TLS settings from certificate, chain certificates, and key files.
tlsSettingsChain ::
  -- | Certificate file
  FilePath ->
  -- | Chain certificate files
  [FilePath] ->
  -- | Key file
  FilePath ->
  TLSSettings
tlsSettingsChain cert chain key =
  defaultTlsSettings
    { tlsCertSettings = CertFromFile cert chain key
    }

-- | Create TLS settings from in-memory PEM data.
tlsSettingsMemory ::
  -- | Certificate PEM
  ByteString ->
  -- | Key PEM
  ByteString ->
  TLSSettings
tlsSettingsMemory cert key =
  defaultTlsSettings
    { tlsCertSettings = CertFromMemory cert [] key
    }

-- | Create TLS settings from in-memory PEM data with chain certificates.
tlsSettingsChainMemory ::
  -- | Certificate PEM
  ByteString ->
  -- | Chain certificate PEMs
  [ByteString] ->
  -- | Key PEM
  ByteString ->
  TLSSettings
tlsSettingsChainMemory cert chain key =
  defaultTlsSettings
    { tlsCertSettings = CertFromMemory cert chain key
    }

--------------------------------------------------------------------------------
-- Session Tickets
--------------------------------------------------------------------------------

{- | Basic ticket key manager with automatic key rotation.

This manager:

* Sets encrypt+decrypt key lifetime to 2 hours
* Sets decrypt-only key lifetime to 13 hours (total key validity of 15 hours)
* Installs an initial key immediately
* Rotates in a new key every 1 hour 59 minutes

The key rotation schedule ensures that:

* New tickets are always encrypted with a key that won't expire for 2 hours
* Old tickets remain valid for decryption during the overlap period
* Gradual key rollover provides seamless session resumption

This is a good default for most server deployments.
-}
basicTicketKeyManager :: TicketKeyOps -> IO (IO ())
basicTicketKeyManager ops = do
  -- Set key lifetimes
  ops.setEncryptLifetime encryptLifetimeSecs
  ops.setDecryptLifetime decryptLifetimeSecs
  -- Install initial key
  installKey 0
  -- Return the rotation action
  pure $ rotateKeys 1
 where
  encryptLifetimeSecs, decryptLifetimeSecs :: Word64
  encryptLifetimeSecs = 2 * 60 * 60 -- 2 hours
  decryptLifetimeSecs = 13 * 60 * 60 -- 13 hours (decrypt-only after encrypt expires)
  rotateIntervalMicros :: Int
  rotateIntervalMicros = (1 * 60 + 59) * 60 * 1_000_000 -- 1:59 in microseconds
  installKey :: Word64 -> IO ()
  installKey counter = do
    -- Generate key name from counter
    let keyName = BS8.pack $ "key" <> show counter
    -- Generate 32 bytes of random key material
    keyData <- getEntropy 32
    -- Add the key
    ops.addTicketKey keyName keyData

  rotateKeys :: Word64 -> IO ()
  rotateKeys counter = do
    threadDelay rotateIntervalMicros
    installKey counter
    rotateKeys (counter + 1)

--------------------------------------------------------------------------------
-- Running TLS
--------------------------------------------------------------------------------

{- | Run a Warp server with TLS support.

This binds to the port specified in 'Settings' (default 3000) and
handles TLS connections using s2n-tls.

The 'S2nTls' handle must be obtained via 'withS2n' or 'withS2nDynamic'.
-}
runTLS :: S2nTls -> TLSSettings -> Settings -> Application -> IO ()
runTLS tls tlsSet settings app = do
  let host = Warp.getHost settings
      port = Warp.getPort settings
  bracket
    (bindPortTCP port host)
    Socket.close
    (\sock -> runTLSSocket tls tlsSet settings sock app)

{- | Run a Warp server with TLS support on an existing socket.

This is useful when you need more control over socket creation,
such as for Unix domain sockets or when using socket activation.

The 'S2nTls' handle must be obtained via 'withS2n' or 'withS2nDynamic'.
-}
runTLSSocket :: S2nTls -> TLSSettings -> Settings -> Socket -> Application -> IO ()
runTLSSocket tls tlsSet@TLSSettings{..} settings sock app = do
  -- Initialize s2n config
  config <- initS2nConfig tls tlsSet

  -- Set up ticket key manager if configured, then run the server
  rotateAction <- case tlsTicketKeyManager of
    Nothing -> pure (pure ()) -- dummy rotation action
    Just keyManager -> do
      -- Turn on session tickets in config since we have a key manager
      tls.setSessionTicketsOnOff config True
      -- Create TicketKeyOps for the key manager
      let ops =
            TicketKeyOps
              { setEncryptLifetime = tls.setTicketEncryptDecryptKeyLifetime config
              , setDecryptLifetime = tls.setTicketDecryptKeyLifetime config
              , addTicketKey = \keyName keyData ->
                  tls.addTicketCryptoKey config keyName keyData Nothing
              }
      -- Call the key manager to set up initial keys and get rotation action
      keyManager ops

  -- Run server with key rotation in background
  withAsync rotateAction $ \_ ->
    WarpI.runSettingsConnectionMakerSecure settings (getter tls config) app
 where
  getter :: S2nTls -> S2N.Config -> IO (IO (WarpI.Connection, WarpI.Transport), SockAddr)
  getter tls' config = do
    (clientSock, clientAddr) <- Socket.accept sock
    let mkConn =
          makeTLSConnection tls' config clientSock clientAddr
            `onException` Socket.close clientSock
    pure (mkConn, clientAddr)

--------------------------------------------------------------------------------
-- Internal: s2n Configuration
--------------------------------------------------------------------------------

-- | Initialize an s2n Config from TLSSettings.
initS2nConfig :: S2nTls -> TLSSettings -> IO S2N.Config
initS2nConfig tls TLSSettings{..} = do
  config <- tls.newConfig

  -- Set cipher preferences
  tls.setCipherPreferences config tlsCipherPreferences

  -- Set client auth type
  tls.setClientAuthType config tlsWantClientCert

  -- Load certificates
  loadCertSettings tls config tlsCertSettings

  pure config

-- | Load certificates into an s2n Config based on CertSettings.
loadCertSettings :: S2nTls -> S2N.Config -> CertSettings -> IO ()
loadCertSettings tls config certSettings = case certSettings of
  CertFromFile certFile chainFiles keyFile -> do
    certPem <- BS.readFile certFile
    keyPem <- BS.readFile keyFile
    chainPems <- mapM BS.readFile chainFiles
    loadCertPems tls config certPem chainPems keyPem
  CertFromMemory certPem chainPems keyPem ->
    loadCertPems tls config certPem chainPems keyPem
  CertFromRef certRef chainRefs keyRef -> do
    certPem <- readIORef certRef
    keyPem <- readIORef keyRef
    chainPems <- mapM readIORef chainRefs
    loadCertPems tls config certPem chainPems keyPem

-- | Load certificate PEMs into config. Chain certs are concatenated with the main cert.
loadCertPems :: S2nTls -> S2N.Config -> ByteString -> [ByteString] -> ByteString -> IO ()
loadCertPems tls config certPem chainPems keyPem = do
  -- s2n expects the full chain in one PEM blob (cert + intermediates)
  let fullChain = BS.concat (certPem : chainPems)
  certKey <- tls.loadCertChainAndKeyPem fullChain keyPem
  tls.addCertChainAndKeyToStore config certKey

--------------------------------------------------------------------------------
-- Internal: Connection Handling
--------------------------------------------------------------------------------

-- | Create a TLS-wrapped Warp Connection from an accepted socket.
makeTLSConnection ::
  S2nTls ->
  S2N.Config ->
  Socket ->
  SockAddr ->
  IO (WarpI.Connection, WarpI.Transport)
makeTLSConnection tls config clientSock clientAddr = do
  -- Create s2n connection
  conn <- tls.newConnection Server
  tls.setConnectionConfig conn config
  tls.setSocket conn clientSock

  -- Perform TLS handshake
  tls.blockingNegotiate conn

  -- Get connection info for Transport
  tlsVersion <- tls.getActualProtocolVersion conn
  alpn <- tls.getApplicationProtocol conn

  -- Create Warp connection
  warpConn <- wrapS2nConnection tls conn clientSock clientAddr

  -- Create transport info
  let (major, minor) = tlsVersionToMajorMinor tlsVersion
      transport =
        WarpI.TLS
          { tlsMajorVersion = major
          , tlsMinorVersion = minor
          , tlsNegotiatedProtocol = BS8.pack <$> alpn
          , tlsChiperID = 0 -- TODO: parse cipher ID from cipher name
          , tlsClientCertificate = Nothing -- TODO: extract from s2n if client auth enabled
          }

  pure (warpConn, transport)

-- | Wrap an s2n Connection as a Warp Connection.
wrapS2nConnection ::
  S2nTls ->
  S2N.Connection ->
  Socket ->
  SockAddr ->
  IO WarpI.Connection
wrapS2nConnection tls conn clientSock clientAddr = do
  writeBuffer <- allocateWriteBuffer
  http2Ref <- newIORef False

  pure
    WarpI.Connection
      { connSendMany = mapM_ (tls.blockingSendAll conn)
      , connSendAll = tls.blockingSendAll conn
      , connSendFile = sendFileTLS tls conn
      , connClose = closeTLSConnection tls conn clientSock
      , connRecv = tls.blockingRecv conn 4096
      , connRecvBuf = recvBufTLS tls conn
      , connWriteBuffer = writeBuffer
      , connHTTP2 = http2Ref
      , connMySockAddr = clientAddr
      }

-- | Receive data into a buffer over TLS.
recvBufTLS :: S2nTls -> S2N.Connection -> WarpI.Buffer -> WarpI.BufSize -> IO Bool
recvBufTLS tls conn buf bufSize = do
  bs <- tls.blockingRecv conn bufSize
  if BS.null bs
    then pure False
    else do
      _ <- WarpI.copy buf bs
      pure True

-- | Send a file over TLS by reading and sending chunks.
sendFileTLS :: S2nTls -> S2N.Connection -> WarpI.FileId -> Integer -> Integer -> IO () -> [ByteString] -> IO ()
sendFileTLS tls conn fileId offset len hook headers = do
  -- Send headers first
  mapM_ (tls.blockingSendAll conn) headers
  -- Read the file portion and send via TLS
  let path = WarpI.fileIdPath fileId
  bs <- withBinaryFile path ReadMode $ \h -> do
    hSeek h AbsoluteSeek (fromIntegral offset)
    BS.hGet h (fromIntegral len)
  tls.blockingSendAll conn bs
  hook

-- | Close a TLS connection properly.
closeTLSConnection :: S2nTls -> S2N.Connection -> Socket -> IO ()
closeTLSConnection tls conn sock = do
  -- Attempt graceful TLS shutdown, ignore errors
  void (shutdownLoop tls conn) `catch` \(_ :: S2nError) -> pure ()
  Socket.close sock
 where
  shutdownLoop t c = do
    result <- t.shutdown c
    case result of
      Right () -> pure ()
      Left BlockedOnRead -> shutdownLoop t c
      Left BlockedOnWrite -> shutdownLoop t c
      Left _ -> pure ()

-- | Convert TlsVersion to (major, minor) for Warp's Transport.
tlsVersionToMajorMinor :: TlsVersion -> (Int, Int)
tlsVersionToMajorMinor v = case v of
  SSLv2 -> (2, 0)
  SSLv3 -> (3, 0)
  TLS10 -> (3, 1)
  TLS11 -> (3, 2)
  TLS12 -> (3, 3)
  TLS13 -> (3, 4)

-- | Allocate a write buffer for Warp Connection.
allocateWriteBuffer :: IO (IORef WarpI.WriteBuffer)
allocateWriteBuffer = WarpI.createWriteBuffer 16_384 >>= newIORef
