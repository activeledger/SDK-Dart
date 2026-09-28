# Changelog

## 1.0.0

- Initial release.
- Port of the JavaScript SDK 2.5: `KeyHandler`, `TransactionHandler`,
  `PayloadHandler`, `Connection` and `Recovery`. No events client: events
  are served on the node's host only.
- secp256k1 (RFC 6979, low-S), ML-DSA-65 in pure Dart, and legacy RSA / PEM
  keys for signing and verifying.
- Falcon-512 via the `activeledger_falcon` add-on and the `PostQuantum`
  registry; `KeyType.preferredPostQuantum` picks the best available.
- `canonicalJson` reproduces JavaScript's `JSON.stringify` byte for byte.
- Tested against the JavaScript SDK's cross-language vectors and a live
  four-node network.
