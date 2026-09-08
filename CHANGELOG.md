# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1.0] - 2026-09-08

### Added
- ALPN protocol advertisement. The server now offers `h2` and `http/1.1`, so
  Warp can select HTTP/2 for clients that request it.

### Changed
- **HTTP/2 is now reachable, where previously it was not.** Warp chooses
  between HTTP/1.1 and HTTP/2 from the ALPN protocol negotiated on the
  `Transport`. No protocol preferences were ever set on the s2n config, so no
  application protocol was negotiated, `tlsNegotiatedProtocol` was always
  `Nothing`, and every connection fell through to HTTP/1.1 regardless of the
  caller's Warp settings.

  The advertised list is derived from Warp's own `settingsHTTP2Enabled`, so
  `setHTTP2Disabled` withdraws `h2` from the offer and restores the previous
  behaviour exactly. Callers that require HTTP/1.1 should set it.

## [0.1.0.0] - 2026-04-28

### Added
- Initial release
