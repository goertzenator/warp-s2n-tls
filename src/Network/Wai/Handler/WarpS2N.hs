{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

{- |
Module      : Network.Wai.Handler.WarpS2N
Copyright   : (c) 2026 Daniel Goertzen
License     : Apache-2.0
Maintainer  : daniel.goertzen@gmail.com
Stability   : experimental
Portability : non-portable (requires s2n-tls C library)

TLS support for Warp via s2n-tls.

This module provides an alternative to @warp-tls@ using AWS's s2n-tls
library for TLS termination.

Basic usage:

@
import Network.Wai.Handler.WarpS2N
import Network.Wai.Handler.Warp (defaultSettings, setPort)

main :: IO ()
main = do
    let tlsSet = tlsSettings "cert.pem" "key.pem"
        warpSet = setPort 443 defaultSettings
    runTLS tlsSet warpSet myApp
@

For dynamic library loading (ie, to pick FIPS or non-FIPS at runtime):

@
main = withS2nTls (Dynamic "/path/to/libs2n.so") $ \\tls -> do
    let tlsSet = tlsSettings "cert.pem" "key.pem"
        warpSet = setPort 443 defaultSettings
    runTLSLib tls tlsSet warpSet myApp
@

= Memory Locking (mlock)

== What is mlock?

s2n-tls uses the Linux @mlock()@ system call to lock memory pages containing
cryptographic secrets (private keys, session keys, etc.) into RAM. This prevents
the operating system from swapping these pages to disk, where they could
potentially be recovered by an attacker after your application terminates.

== The RLIMIT_MEMLOCK Limit

Linux enforces a per-process limit on how much memory can be locked, controlled
by @RLIMIT_MEMLOCK@. On many systems, this defaults to just __64 KB__ (or even
32 KB on some Debian versions). Since s2n-tls locks memory for all TLS
connections and cryptographic operations, this limit can be exhausted quickly
in applications handling multiple connections.

When the limit is exceeded, you'll see errors like:

> Error Message: 'error calling mlock'
> Debug String: 'Error encountered in s2n_mem.c line 106'

== Solutions

__Option 1: Increase the mlock limit (recommended for production)__

Raise the limit for your shell session:

> ulimit -l unlimited

Or set it to a specific value (in KB):

> ulimit -l 65536  # 64 MB

For systemd services, add to your unit file:

> [Service]
> LimitMEMLOCK=infinity

For persistent user limits, add to @\/etc\/security\/limits.conf@:

> youruser  soft  memlock  unlimited
> youruser  hard  memlock  unlimited

__Option 2: Disable mlock (acceptable for development\/testing)__

Set the environment variable to disable memory locking entirely:

> S2N_DONT_MLOCK=1 ./your-application

== Security Considerations

* __With mlock enabled__: Secrets are protected from being written to swap,
  reducing the risk of recovery from disk. This is the recommended setting
  for production deployments handling sensitive data.

* __With mlock disabled__: Secrets may be swapped to disk under memory
  pressure. This is generally acceptable for development, testing, and
  applications where the threat model doesn't include disk forensics.

* __Note__: Even with mlock enabled, laptop suspend\/hibernate modes may
  save RAM contents to disk regardless of memory locks.

== Running Tests

Tests may exhaust the default mlock limit. Use:

> S2N_DONT_MLOCK=1 cabal test
-}
module Network.Wai.Handler.WarpS2N (
  -- * Running TLS
  runTLS,
  runTLSSocket,
  runTLSLib,
  runTLSSocketLib,

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

import Control.Concurrent.Async (withAsync)
import Control.Concurrent.Thread.Delay (delay)
import Control.Exception (bracket, catch, onException)
import Control.Monad (void)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BS8
import Data.IORef (IORef, newIORef)
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

{- | Operations available to a ticket key manager.

This record provides an abstraction over the underlying TLS library,
allowing key managers to configure ticket encryption without depending
on s2n-tls internals.
-}
data TicketKeyOps = TicketKeyOps
  { setEncryptDecryptLifetime :: Word64 -> IO ()
  -- ^ Set the lifetime (in seconds) for which a key can both encrypt and decrypt tickets.
  -- After this time, the key will only be used for decryption.
  , setDecryptLifetime :: Word64 -> IO ()
  -- ^ Set the lifetime (in seconds) for which a key can decrypt tickets
  -- after it can no longer encrypt. Total key validity is encrypt/decrypt + decrypt lifetime.
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

-- | TLS settings for the server.
data TLSSettings = TLSSettings
  { tlsCertSettings :: !CertSettings
  -- ^ Certificate configuration (cert, chain, key).
  , tlsCipherPreferences :: !String
  -- ^ s2n cipher policy name (e.g., "default_tls13", "default").
  -- See s2n documentation for available policies.
  , tlsWantClientCert :: !CertAuthType
  -- ^ Client certificate authentication type.
  , tlsTicketKeyManager :: !(Maybe (TicketKeyOps -> IO (IO ())))
  -- ^ Optional ticket key manager for session resumption via tickets.
  -- This callback registers an initial ticket key and returns a forever running action that adds new keys over time.
  }

{- | Default TLS settings.

* Loads certificate from @certificate.pem@ and key from @key.pem@
* Uses @default_tls13@ cipher policy
* No client certificate authentication
* Uses 'basicTicketKeyManager' with 2 hour encrypt\/decrypt and 13 hour decrypt lifetimes
-}
defaultTlsSettings :: TLSSettings
defaultTlsSettings =
  TLSSettings
    { tlsCertSettings = CertFromFile "certificate.pem" [] "key.pem"
    , tlsCipherPreferences = "default_tls13"
    , tlsWantClientCert = CertAuthNone
    , tlsTicketKeyManager = Just $ basicTicketKeyManager (2 * 60 * 60) (13 * 60 * 60)
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

Parameters:

* @encryptDecryptLifetimeSecs@: How long (in seconds) a key can both encrypt and decrypt tickets
* @decryptLifetimeSecs@: How long (in seconds) a key can decrypt after it stops encrypting

This manager:

* Sets the encrypt\/decrypt and decrypt lifetimes as specified
* Installs an initial key immediately
* Rotates in a new key every @encryptDecryptLifetimeSecs / 2@ seconds

The key rotation schedule ensures that:

* New tickets are always encrypted with a key that won't expire soon
* Old tickets remain valid for decryption during the overlap period
* Gradual key rollover provides seamless session resumption
-}
basicTicketKeyManager :: Word64 -> Word64 -> TicketKeyOps -> IO (IO ())
basicTicketKeyManager encryptDecryptLifetimeSecs decryptLifetimeSecs ops = do
  -- Set key lifetimes
  ops.setEncryptDecryptLifetime encryptDecryptLifetimeSecs
  ops.setDecryptLifetime decryptLifetimeSecs
  -- Install initial key
  installKey 0
  -- Return the rotation action
  pure $ rotateKeys 1
 where
  rotateIntervalMicros :: Integer
  rotateIntervalMicros = fromIntegral encryptDecryptLifetimeSecs * 1_000_000 `div` 2

  installKey :: Word64 -> IO ()
  installKey counter = do
    let keyName = BS8.pack $ "key" <> show counter
    keyData <- getEntropy 32
    ops.addTicketKey keyName keyData

  rotateKeys :: Word64 -> IO ()
  rotateKeys counter = do
    delay rotateIntervalMicros
    installKey counter
    rotateKeys (counter + 1)

--------------------------------------------------------------------------------
-- Running a Warp Server with TLS
--------------------------------------------------------------------------------

{- | Run a Warp server with TLS support.

This is the simplest way to run a TLS server. It initializes the s2n-tls
library, binds to the port specified in 'Settings', and
handles TLS connections.

@
import Network.Wai.Handler.WarpS2N
import Network.Wai.Handler.Warp (defaultSettings, setPort)

main :: IO ()
main = do
    let tlsSet = tlsSettings "cert.pem" "key.pem"
        warpSet = setPort 443 defaultSettings
    runTLS tlsSet warpSet myApp
@
-}
runTLS :: TLSSettings -> Settings -> Application -> IO ()
runTLS tlsSet settings app =
  withS2nTls Linked $ \tls ->
    runTLSLib tls tlsSet settings app

{- | Run a Warp server with TLS support on an existing socket.

This is useful when you need more control over socket creation,
such as for Unix domain sockets or when using socket activation.
Initializes s2n-tls automatically.
-}
runTLSSocket :: TLSSettings -> Settings -> Socket -> Application -> IO ()
runTLSSocket tlsSet settings sock app =
  withS2nTls Linked $ \tls ->
    runTLSSocketLib tls tlsSet settings sock app

{- | Run a Warp server with TLS support, using an existing 'S2nTls' handle.

This binds to the port specified in 'Settings' and
handles TLS connections using s2n-tls.

Use this when the specific s2n-tls library will be dynamically selected at runtime.
-}
runTLSLib :: S2nTls -> TLSSettings -> Settings -> Application -> IO ()
runTLSLib tls tlsSet settings app = do
  let host = Warp.getHost settings
      port = Warp.getPort settings
  bracket
    (bindPortTCP port host)
    Socket.close
    (\sock -> runTLSSocketLib tls tlsSet settings sock app)

{- | Run a Warp server with TLS support on an existing socket, using an existing 'S2nTls' handle.

This is useful when you need more control over socket creation,
such as for Unix domain sockets or when using socket activation.

Use this when the specific s2n-tls library will be dynamically selected at runtime
-}
runTLSSocketLib :: S2nTls -> TLSSettings -> Settings -> Socket -> Application -> IO ()
runTLSSocketLib tls tlsSet@TLSSettings{..} settings sock app = do
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
              { setEncryptDecryptLifetime = tls.setTicketEncryptDecryptKeyLifetime config
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
  void (tls.blockingShutdown conn) `catch` \(_ :: S2nError) -> pure ()
  Socket.close sock

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
