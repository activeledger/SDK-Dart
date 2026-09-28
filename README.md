<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/activeledger/activeledger/master/docs/assets/Asset-23-dark.png">
  <img src="https://raw.githubusercontent.com/activeledger/activeledger/master/docs/assets/Asset-23.png" alt="Activeledger" width="300"/>
</picture>

# Activeledger SDK for Dart

Dart and Flutter SDK for [Activeledger](https://github.com/activeledger/activeledger), with post-quantum identity support.

| Package | What it is |
|---|---|
| [`activeledger`](packages/activeledger) | The SDK: keys, onboarding, transactions, payload signing. secp256k1 and ML-DSA-65 in pure Dart. |
| [`activeledger_falcon`](packages/activeledger_falcon) | Adds Falcon-512, backed by liboqs with bundled native libraries. |

```dart
import 'package:activeledger_falcon/activeledger_falcon.dart';

Future<void> main() async {
  ActiveledgerFalcon.enable(); // optional - falls back to ML-DSA-65

  final ledger = Activeledger('http://localhost:5260');
  final key = ledger.generateKey('identity', type: KeyType.preferredPostQuantum);
  await ledger.onboard(key);
  print(key.identity);
}
```

See [the `activeledger` package README](packages/activeledger/README.md) for
the full guide.

## Compatibility

A port of the [JavaScript SDK](https://github.com/activeledger/SDK-JS), which
is the reference implementation. Same handlers, same key file format, and the
same bytes: `vectors/` holds the JavaScript SDK's cross-language vectors,
copied unmodified, and both packages are tested against them - canonical JSON
and number formatting, signatures for all three schemes, and key derivation
from seeds and recovery phrases. Both packages are also tested against a real
four-node Activeledger network.

## Development

```bash
dart pub get
dart analyze
dart test packages/activeledger
dart test packages/activeledger_falcon
```

## Licence

MIT
