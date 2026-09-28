<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/activeledger/activeledger/master/docs/assets/Asset-23-dark.png">
  <img src="https://raw.githubusercontent.com/activeledger/activeledger/master/docs/assets/Asset-23.png" alt="Activeledger" width="300"/>
</picture>

[![pub](https://img.shields.io/pub/v/activeledger)](https://pub.dev/packages/activeledger)
[![licence](https://img.shields.io/badge/licence-MIT-blue)](https://github.com/activeledger/SDK-Dart/blob/master/LICENSE)

# Activeledger SDK for Dart

Dart and Flutter SDK for [Activeledger](https://github.com/activeledger/activeledger), with post-quantum identity support.

**Requires Activeledger 4.7.0+** for `ml-dsa-65` and `falcon-512`. Dart 3.10+.

A port of the [JavaScript SDK](https://github.com/activeledger/SDK-JS): the
same handlers (`KeyHandler`, `TransactionHandler`, `PayloadHandler`,
`Connection`, `LedgerEvents`), the same key file format, and byte-for-byte the
same signatures, checked against the JavaScript SDK's cross-language vectors
and against a real four-node network.

---

## Install

```bash
dart pub add activeledger
```

For Falcon-512 as well, add the add-on. Its native library is downloaded and
bundled automatically for Android, iOS, macOS, Linux and Windows:

```bash
dart pub add activeledger_falcon
```

## Quick start

```dart
import 'package:activeledger/activeledger.dart';

final ledger = Activeledger('http://localhost:5260');

final key = ledger.generateKey('identity', type: KeyType.mlDsa65);
await ledger.onboard(key);
print(key.identity); // the new identity's stream id
```

With the Falcon add-on:

```dart
import 'package:activeledger_falcon/activeledger_falcon.dart';

ActiveledgerFalcon.enable();   // once, at startup
final key = ledger.generateKey('identity', type: KeyType.preferredPostQuantum);
```

`KeyType.preferredPostQuantum` is Falcon-512 when the add-on is enabled and
ML-DSA-65 otherwise, so the same code runs either way.

---

## Key types

| Key type | Wire string | Public | Private | Signature | Encoding |
|---|---|---|---|---|---|
| secp256k1 | `secp256k1` | 33 or 65 | 32 | ~70-72, variable DER | `0x` hex |
| ML-DSA-65 | `ml-dsa-65` | 1952 | 4032 | 3309 | base64 |
| Falcon-512 | `falcon-512` | 897 | 1281 | 649-662, variable | base64 |
| RSA (legacy) | `rsa` | PEM | PEM | 256 for 2048-bit | PEM |

Use **secp256k1** unless the identity must outlive a cryptographically
relevant quantum computer: roughly **22x smaller** per transaction than
ML-DSA-65, and every byte is stored on the ledger permanently and replicated
to every node. Between the post-quantum schemes, **Falcon-512** signatures are
about a fifth the size of ML-DSA-65's; ML-DSA-65 is the finalised standard and
needs no native code.

```dart
final keys = KeyHandler();

final ec = keys.generateKey('me');                       // secp256k1, uncompressed
final ec33 = keys.generateKey('me', compressed: true);   // 33-byte public key
final pq = keys.generateKey('me', type: KeyType.mlDsa65);

ec.key.publicKey;    // "0x04a1b2..." - give this to the ledger
ec.key.privateKey;   // keep this
```

- **secp256k1 keys are `0x`-prefixed hex; post-quantum keys are base64** of
  the raw algorithm bytes. The prefix is required, not tolerated.
- **secp256k1 signing is RFC 6979 deterministic and low-S**, so its signatures
  are byte-identical to `@noble/curves` for the same key and message.
  **Verification accepts high-S**, because the ledger verifies through
  OpenSSL and produces high-S freely.
- **Post-quantum signing is hedged**: two signatures over one message differ,
  and both verify. Falcon signature length varies - never assume it fixed.
- **RSA** keys (a network's contract deployer, say) sign and verify from PEM.
  They cannot be generated. secp256k1 keys exported as PEM by older SDKs work
  too.
- `KeyType.fromWire` parses `bitcoin` and `ethereum` as secp256k1, because
  the ledger routes them to identical verification. They are never emitted.

---

## Seeds and recovery phrases

```dart
final keys = KeyHandler();

final key = keys.generateBip39Key('me', type: KeyType.mlDsa65);
print(key.phrase);                                     // 12 words - store them

final same = keys.restoreBip39Key('me', key.phrase!, type: KeyType.mlDsa65);
final withPass = keys.restoreBip39Key('me', phrase, passphrase: 'extra words');

final fromSeed = keys.generateKeyFromSeed('me', seed32, type: KeyType.mlDsa65);
```

The same seed gives the same identity in **every** Activeledger SDK, which
makes a seed the portable private-key format. One phrase can back a
secp256k1, an ml-dsa-65 and a falcon-512 identity at once, each derived
independently:

| Type | Seed from the BIP-39 seed `S` |
|---|---|
| `secp256k1` | `HMAC-SHA512("Bitcoin seed", S)[0..32]` |
| `ml-dsa-65` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:ml-dsa-65", 32)` |
| `falcon-512` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:falcon-512", 48)` |

`Recovery` exposes each step - `validate`, `toSeed`, `deriveSeed`,
`deriveBip32MasterKey`, `generateMnemonic` - so you can see which one differs
when a recovered identity is not the expected one.

- A seed of the wrong length is **refused, not padded**: a padded seed is a
  different identity, not a malformed one.
- For secp256k1 the seed **is** the private scalar, so a seed of zero or at or
  above the curve order is refused rather than reduced mod *n*.
- Phrases are validated, wordlist **and** checksum. A mistyped phrase that is
  not checked derives a valid key for an identity nobody owns. Pass
  `validate: false` only to derive from a string that is not a mnemonic.
- `legacy: true` recovers a phrase made by the old `@activeledger/sdk-bip39`
  package (SHA256 of the phrase). Recovery only, never for new keys.

---

## Transactions

```dart
final transactions = TransactionHandler();

final tx = transactions.labelledTransaction(
  key: key,                        // must be onboarded
  namespace: 'mynamespace',
  contract: 'mycontract',
  inputLabel: 'input',
  stream: key.identity!,
  inputData: {'message': 'hello'},
  outputs: {'target-stream': {'amount': 10}},
  entry: 'update',                 // optional $entry
);

final response = await connection.sendTransaction(tx);
if (!response.committed) throw Exception(response.errors);

response.streams.created;   // streams created
response.responses;         // returnToRemote values
```

For any other shape - several inputs, several signers - build the `$tx`
yourself and sign it once per key:

```dart
final tx = Transaction(tx: {
  r'$namespace': 'ns',
  r'$contract': 'c',
  r'$i': {alice.identity!: {}, bob.identity!: {}},
});
transactions.signTransaction(tx, alice);
transactions.signTransaction(tx, bob);
```

`$sigs` is keyed by identity, or by `$i` label for a self-signed
transaction (`selfsign: true`), which is what the ledger looks up.

### Reading state

There is no separate read API: a node's storage service listens only on the
node's own host. Name the streams in `readonly` (`$r`) and have the contract
return values with `returnToRemote`; they arrive in `response.responses`.

---

## Events

ActiveCore serves events, by default on port 5261:

```dart
final events = LedgerEvents('http://localhost:5261');

// As streams - cancelling closes the connection.
final sub = events.activity().listen(print);
events.events(contract: 'mycontract', event: 'transfer').listen(print);

// Or with callbacks, as in the JavaScript SDK.
final id = events.subscribeToActivity((stream) => print(stream));
events.errors.listen(print);
events.unsubscribe(id);
```

Connections reconnect after a drop, resuming from the last event id.

---

## Signing payloads

```dart
final payloads = PayloadHandler();

final signature = payloads.sign({'pair': 'VNR/USDT', 'side': 'sell'}, key);
payloads.verify(order, signature, publicKey, type: KeyType.mlDsa65);   // bool
```

`payloads.canonical(order)` is the exact string signed. It is key-order
sensitive, so persist it alongside the signature and verify that.

## Key files

```dart
await keys.exportKey(key, 'keys', createDir: true);     // keys/<name>.json
final loaded = await keys.importKey('keys/identity.json');
```

The format is the JavaScript SDK's, so key files move between the two.

## Signing elsewhere

Every handler takes a `CryptoProvider`. Implement one to sign in an HSM or
secure enclave, or register a custom `PostQuantumScheme` with
`PostQuantum.register`.

---

## Things that will bite you

**Always send the key type.** The ledger defaults a missing `type` to `rsa`.
This SDK always sends it; if you hand-build an envelope, do the same.

**A rejected transaction is HTTP 200.** Check `response.committed`, never the
status code.

**Errors are unhelpful by design.** A wrong type string, a wrong-length key or
signed bytes differing by one escape all come back as **1220 "Signature
Incorrect"**. This SDK validates key lengths and type strings up front so
these fail locally with a message naming the problem.

**Signatures cover `$tx` only**, not the envelope. `tx.signedString` is exactly
what was signed, which is the fastest way to diagnose a 1220.

## Canonical JSON

Signatures cover the exact bytes of JavaScript's `JSON.stringify($tx)`. Dart's
`jsonEncode` differs from it on numbers - `1.0` versus `1`, `1e20` versus
`100000000000000000000.0` - so `canonicalJson` reproduces `JSON.stringify`
exactly. It is checked against the cross-language number vectors and against
Node on tens of thousands of random doubles. It refuses `NaN`, infinities and
integers a JavaScript number cannot hold, rather than signing something you
did not write.

---

## Testing

```bash
dart test
```

Integration tests run against a real network. From an `activeledger`
checkout, `npm run test:network:serve`, then:

```bash
AL_NODES=http://127.0.0.1:5510 AL_STORAGE=http://127.0.0.1:5509 dart test test/integration
```

## Licence

MIT
