# Changelog

## 1.0.0

- Initial release.
- Port of the JavaScript SDK 2.5: `KeyHandler`, `TransactionHandler`,
  `PayloadHandler`, `Connection`, `LedgerEvents`, and `Recovery`.
- secp256k1 (RFC 6979, low-S), ML-DSA-65 in pure Dart, and legacy RSA / PEM
  keys for signing and verifying.
- Falcon-512 via the `activeledger_falcon` add-on and the `PostQuantum`
  registry; `KeyType.preferredPostQuantum` picks the best available.
- `canonicalJson` reproduces JavaScript's `JSON.stringify` byte for byte.
- `LedgerEvents` streams contract events from the node's own database;
  `ActiveCoreEvents` covers legacy ActiveCore deployments.
- Tested against the JavaScript SDK's cross-language vectors and a live
  four-node network.
