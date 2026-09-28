# Falcon-512 for the Activeledger Dart SDK

[![pub](https://img.shields.io/pub/v/activeledger_falcon)](https://pub.dev/packages/activeledger_falcon)
[![licence](https://img.shields.io/badge/licence-MIT-blue)](https://github.com/activeledger/SDK-Dart/blob/main/LICENSE)

Adds `falcon-512` (FN-DSA) keys to [`activeledger`](https://pub.dev/packages/activeledger).

Falcon-512 signatures are about a fifth the size of ML-DSA-65's, which matters
on a ledger: every signature is broadcast to every node and stored for good.

## Install

```bash
dart pub add activeledger_falcon
```

Backed by [liboqs](https://github.com/open-quantum-safe/liboqs) through the
[`liboqs`](https://pub.dev/packages/liboqs) package, whose prebuilt native
libraries are downloaded and bundled by Dart's build hooks - there is nothing
to install or compile. Supported on Android, iOS, macOS, Linux and Windows.

## Use

```dart
import 'package:activeledger_falcon/activeledger_falcon.dart';

void main() {
  ActiveledgerFalcon.enable();

  final key = KeyHandler().generateKey('identity', type: KeyType.falcon512);
}
```

This library re-exports `package:activeledger`, so one import is enough.

`enable()` loads the native library, runs a sign-and-verify self-test and
registers the scheme. If the library cannot be loaded it returns `false` and
the SDK stays on ML-DSA-65 - so code written with
`KeyType.preferredPostQuantum` works either way:

```dart
ActiveledgerFalcon.enable();
final key = keys.generateKey('identity', type: KeyType.preferredPostQuantum);
```

## What it guarantees

- **Ledger byte forms.** Keys include their 1-byte header, 897 and 1281
  bytes. Signatures are the compressed, variable-length form (649-662 bytes) -
  liboqs's `Falcon-512`, not `Falcon-padded-512`.
- **Portable seeds.** `generateKeyFromSeed` and `restoreBip39Key` produce the
  same Falcon key from the same 48-byte seed as the JavaScript and JVM SDKs,
  checked against the cross-language seed vectors.
- **Verified against a real network**: onboarding, transactions and a
  tampered-payload rejection on a four-node Activeledger network.

One caveat: liboqs has no seeded key generation, so deriving a key from a seed
points liboqs's random source at the seed for the duration of the call. That
source is process-wide - avoid running other liboqs operations on other
isolates at the same moment. Random key generation and signing are
unaffected.

## Licence

MIT. liboqs is MIT licensed.
