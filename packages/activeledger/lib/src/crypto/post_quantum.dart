import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';

import '../errors.dart';
import '../key_type.dart';
import 'random.dart';

/// A post-quantum signature scheme, operating on raw key and signature bytes.
///
/// ML-DSA-65 ships with this package. Falcon-512 is provided by the
/// `activeledger_falcon` add-on, which implements this interface and calls
/// [PostQuantum.register]. A custom implementation (an HSM, a different
/// native library) can be registered the same way.
///
/// Implementations must produce the exact byte forms the ledger uses: for
/// Falcon that means keys WITH their 1-byte header (897 / 1281 bytes).
abstract interface class PostQuantumScheme {
  /// The key type this scheme implements.
  KeyType get type;

  /// Raw public key length in bytes.
  int get publicKeyBytes;

  /// Raw private key length in bytes.
  int get privateKeyBytes;

  /// The length of the algorithm's own key generation seed.
  int get seedBytes;

  /// A fresh key pair from a secure random source.
  ({Uint8List publicKey, Uint8List privateKey}) generate();

  /// The key pair determined by [seed], which is exactly [seedBytes] long.
  ///
  /// No KDF is applied: the same seed gives the same identity in every
  /// Activeledger SDK, which is what makes a seed the portable private key
  /// format.
  ({Uint8List publicKey, Uint8List privateKey}) fromSeed(Uint8List seed);

  /// Signs [message]. Hedged (randomised), matching the reference SDK.
  Uint8List sign(Uint8List message, Uint8List privateKey);

  /// Verifies [signature]. Returns false, rather than throwing, for
  /// malformed input.
  bool verify(Uint8List message, Uint8List signature, Uint8List publicKey);
}

/// The registry of post-quantum schemes available in this process.
///
/// ML-DSA-65 is always present. Falcon-512 appears once the
/// `activeledger_falcon` package's `ActiveledgerFalcon.enable()` has run.
abstract final class PostQuantum {
  static final Map<KeyType, PostQuantumScheme> _schemes = {
    KeyType.mlDsa65: MlDsa65Scheme(),
  };

  /// Makes [scheme] available for its key type, replacing any existing one.
  static void register(PostQuantumScheme scheme) {
    if (!scheme.type.isPostQuantum) {
      throw ArgumentError.value(
        scheme.type,
        'scheme.type',
        'is not a post-quantum key type',
      );
    }
    _schemes[scheme.type] = scheme;
  }

  /// Removes the scheme for [type]. ML-DSA-65 reverts to the built-in one.
  static void unregister(KeyType type) {
    _schemes.remove(type);
    if (type == KeyType.mlDsa65) _schemes[type] = MlDsa65Scheme();
  }

  /// Whether [type] can be used in this process.
  static bool isAvailable(KeyType type) => _schemes.containsKey(type);

  /// The scheme for [type], or a [KeyTypeUnavailableException] naming what
  /// is missing.
  static PostQuantumScheme schemeFor(KeyType type) {
    final scheme = _schemes[type];
    if (scheme != null) return scheme;
    if (type == KeyType.falcon512) {
      throw KeyTypeUnavailableException(
        'falcon-512 is not available. Add the activeledger_falcon package and '
        'call ActiveledgerFalcon.enable() at startup - or use '
        'KeyType.preferredPostQuantum, which falls back to ml-dsa-65.',
      );
    }
    throw KeyTypeUnavailableException(
      '${type.wire} is not a post-quantum type',
    );
  }
}

/// ML-DSA-65 (FIPS 204), in pure Dart.
///
/// Signing is HEDGED: a fresh 32-byte `rnd` from a secure random source on
/// every call, as the JavaScript reference does. FIPS 204 permits a
/// deterministic variant; it is deliberately not used, so two signatures
/// over the same message differ and both verify.
///
/// Private keys are the 4032-byte FIPS 204 encoding. Key generation from the
/// 32-byte seed agrees with `@noble/post-quantum`, BouncyCastle and Rust's
/// `fips204`, checked against the cross-language seed vectors.
final class MlDsa65Scheme implements PostQuantumScheme {
  static const _params = DilithiumParams.mlDsa65;

  @override
  KeyType get type => KeyType.mlDsa65;

  @override
  int get publicKeyBytes => 1952;

  @override
  int get privateKeyBytes => 4032;

  @override
  int get seedBytes => 32;

  @override
  ({Uint8List publicKey, Uint8List privateKey}) generate() =>
      fromSeed(secureRandomBytes(seedBytes));

  @override
  ({Uint8List publicKey, Uint8List privateKey}) fromSeed(Uint8List seed) {
    if (seed.length != seedBytes) {
      throw ArgumentError(
        'ml-dsa-65 needs a $seedBytes-byte seed, got ${seed.length}',
      );
    }
    final (pk, sk) = MlDsa.generateKeyPairSeeded(_params, seed);
    return (publicKey: pk, privateKey: sk);
  }

  @override
  Uint8List sign(Uint8List message, Uint8List privateKey) {
    if (privateKey.length != privateKeyBytes) {
      throw ArgumentError(
        'ml-dsa-65 private key should be $privateKeyBytes '
        'bytes, got ${privateKey.length}',
      );
    }
    return MlDsa.sign(privateKey, message, _params, rnd: secureRandomBytes(32));
  }

  @override
  bool verify(Uint8List message, Uint8List signature, Uint8List publicKey) {
    if (publicKey.length != publicKeyBytes) return false;
    try {
      return MlDsa.verify(publicKey, message, signature, _params);
    } catch (_) {
      return false;
    }
  }
}
