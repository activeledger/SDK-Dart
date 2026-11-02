# Changelog

## 1.1.0

### Changed behaviour

- **A reply is committed only if it is a 2xx JSON object with a `$summary` object whose `errors` are absent or empty.** A `{}` body or any body without `$summary` is not committed, and `commit > 0` is no longer required. A ledger rejection delivered as HTTP 200 still reports not committed. A 2xx body that is not JSON now throws `ActiveledgerException` instead of `FormatException`. What to do: catch `ActiveledgerException` where you caught `FormatException` around `sendTransaction`.
- **`onboardKey` throws `OnboardException` when the reply did not commit**, even if a stream id is present, matching the JavaScript, PHP and Swift SDKs. The identity is left unset. What to do: handle the exception, or check the ledger errors it carries.
- **`Key.fromJson` and `importKey` check that the public key belongs to the private key** (secp256k1: the public key derived from the scalar; ml-dsa-65: a sign and verify round trip). A mismatch throws `FormatException`. What to do: re-export key files that were assembled by hand.
- **secp256k1 public keys are validated as points** (coordinates below p, on the curve, not infinity). Off-curve points that were accepted before are rejected by `fromPublic`, `fromKeys` and `verify`.

### Fixed

- A valid base64 post-quantum key whose text begins `0x` (about 1 in 4096 ML-DSA and Falcon keys) was rejected as hex. Base64 is now tried first.
- `LedgerResponse` accessors (`umid`, `responses`, summary numbers, stream references) threw a cast error on wrongly typed fields; they now return null or empty.

### Tests and CI

- Unit tests for responses, the connection against an in-process loopback server, envelopes, key files, DER and the Falcon add-on boundary.
- `scripts/smoke.dart` (a throwaway consumer package using path dependencies) runs in CI.
- The README links to the hosted documentation.

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
