/// The Activeledger SDK for Dart and Flutter.
///
/// Onboard identities, sign and submit transactions, sign payloads and
/// subscribe to ledger events, with secp256k1 and post-quantum ML-DSA-65
/// keys. Falcon-512 is available through the `activeledger_falcon` add-on.
library;

export 'src/activeledger.dart';
export 'src/canonical.dart' show canonicalJson, canonicalJsonBytes, jsNumber;
export 'src/connection.dart';
export 'src/crypto/crypto_provider.dart';
export 'src/crypto/post_quantum.dart';
export 'src/crypto/secp256k1.dart' show Secp256k1;
export 'src/errors.dart';
export 'src/events.dart';
export 'src/key.dart';
export 'src/key_type.dart';
export 'src/payload.dart';
export 'src/recovery.dart';
export 'src/transaction.dart';
