# warp-s2n-tls

TLS support for the Warp web server using [s2n-tls](https://github.com/aws/s2n-tls).

## Overview

This library provides an alternative to `warp-tls` by using AWS's s2n-tls
library for TLS termination instead of the Haskell `tls` package.

## Installation

Add to your cabal file:

```cabal
build-depends: warp-s2n-tls
```

## Usage

```haskell
import Network.Wai.Handler.WarpS2N
import Network.Wai.Handler.Warp (defaultSettings, setPort)
import Network.Wai (Application)

main :: IO ()
main = withS2nTls Linked $ \tls -> do
    let tlsSet = tlsSettings "cert.pem" "key.pem"
        warpSet = setPort 443 defaultSettings
    runTLS tls tlsSet warpSet myApp

myApp :: Application
myApp = ...
```

### Using in-memory certificates

```haskell
import qualified Data.ByteString as BS

main :: IO ()
main = withS2nTls Linked $ \tls -> do
    cert <- BS.readFile "cert.pem"
    key <- BS.readFile "key.pem"
    let tlsSet = tlsSettingsMemory cert key
    runTLS tls tlsSet defaultSettings myApp
```

### With chain certificates

```haskell
-- From files
let tlsSet = tlsSettingsChain "cert.pem" ["intermediate.pem"] "key.pem"

-- From memory
let tlsSet = tlsSettingsChainMemory certPem [intermediatePem] keyPem
```

### Running multiple servers

The s2n handle can be shared across multiple servers:

```haskell
import Control.Concurrent.Async (concurrently_)

main :: IO ()
main = withS2nTls Linked $ \tls -> do
    let tlsSet1 = tlsSettings "cert1.pem" "key1.pem"
        tlsSet2 = tlsSettings "cert2.pem" "key2.pem"
    concurrently_
        (runTLS tls tlsSet1 (setPort 443 defaultSettings) app1)
        (runTLS tls tlsSet2 (setPort 8443 defaultSettings) app2)
```

### Dynamic library loading

To load libs2n.so at runtime instead of linking:

```haskell
main :: IO ()
main = withS2nTls (Dynamic "/usr/local/lib/libs2n.so") $ \tls -> do
    runTLS tls tlsSet warpSet myApp
```

## Configuration

### TLSSettings fields

- `tlsCertSettings` - Certificate configuration (see `CertSettings`)
- `tlsCipherPreferences` - s2n cipher policy (default: `"default_tls13"`)
- `tlsWantClientCert` - Client certificate auth (default: `CertAuthNone`)
- `tlsSessionManager` - Session resumption callbacks (default: `Nothing`)

### CertSettings

- `CertFromFile certPath chainPaths keyPath` - Load from files
- `CertFromMemory certPem chainPems keyPem` - In-memory PEM data
- `CertFromRef certRef chainRefs keyRef` - Dynamic via IORefs

### Cipher Policies

Common s2n cipher policies:
- `"default"` - Default policy
- `"default_tls13"` - TLS 1.3 preferred (recommended)
- `"20170210"` - Specific dated policy

See s2n-tls documentation for the full list.

## Development

### Running tests

Tests require the `S2N_DONT_MLOCK=1` environment variable to avoid lockable memory
exhaustion issues:

```bash
S2N_DONT_MLOCK=1 cabal test
```

## Known Limitations

1. **Session resumption**: The `SessionManager` type is defined but not yet
   wired to s2n's session cache callbacks. This requires low-level FFI work.

## License

BSD-3-Clause
