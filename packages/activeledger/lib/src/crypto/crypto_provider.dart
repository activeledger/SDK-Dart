import 'dart:convert';
import 'dart:typed_data';

import '../key_type.dart';
import '../key.dart';
import 'der.dart';
import 'pem_keys.dart';
import 'post_quantum.dart';
import 'secp256k1.dart';

/// Generates keys and signs and verifies strings - the Dart counterpart of
/// the JavaScript SDK's `ICryptoProvider`.
///
/// The handlers ([KeyHandler], [TransactionHandler], [PayloadHandler]) take
/// one of these and default to [DefaultCryptoProvider]. Supply your own to
/// sign somewhere else - an HSM, a secure enclave - without touching
/// anything else.
abstract interface class CryptoProvider {
  /// A fresh key of [type]. [compressed] applies to secp256k1 only.
  KeyMaterial generate({
    KeyType type = KeyType.secp256k1,
    bool compressed = false,
  });

  /// The key determined by the algorithm's own [seed]: 32 bytes for
  /// secp256k1 and ml-dsa-65, 48 for falcon-512. No KDF is applied, and a
  /// wrong length is refused - never padded or truncated into a different
  /// identity.
  KeyMaterial generateFromSeed(
    Uint8List seed, {
    KeyType type = KeyType.secp256k1,
    bool compressed = false,
  });

  /// Signs the UTF-8 bytes of [data] and returns the signature as base64,
  /// ready for `$sigs`.
  String sign(
    String data,
    String privateKey, {
    KeyType type = KeyType.secp256k1,
  });

  /// Verifies a base64 [signature] over the UTF-8 bytes of [data]. Returns
  /// false, never throws, for a malformed signature or key.
  bool verify(
    String data,
    String signature,
    String publicKey, {
    KeyType type = KeyType.secp256k1,
  });
}

/// The built-in [CryptoProvider].
///
/// - **secp256k1**: keys are `0x` hex; signing is RFC 6979 deterministic
///   with low-S, SHA-256 then ECDSA then DER; verification accepts high-S.
///   PEM keys (as older SDKs exported) are accepted for signing and
///   verifying.
/// - **ml-dsa-65** and **falcon-512**: keys are base64 raw bytes; signing
///   is hedged. Falcon needs the `activeledger_falcon` add-on.
/// - **rsa**: sign and verify with existing PEM keys only (PKCS#1 v1.5,
///   SHA-256). Generation is refused.
class DefaultCryptoProvider implements CryptoProvider {
  const DefaultCryptoProvider();

  @override
  KeyMaterial generate({
    KeyType type = KeyType.secp256k1,
    bool compressed = false,
  }) {
    if (type.isPostQuantum) {
      final keys = PostQuantum.schemeFor(type).generate();
      return KeyMaterial(
        publicKey: base64.encode(keys.publicKey),
        privateKey: base64.encode(keys.privateKey),
      );
    }
    _requireSecp256k1(type);
    final keys = Secp256k1.generate(compressed: compressed);
    return KeyMaterial(
      publicKey: Secp256k1.toHex(keys.publicKey),
      privateKey: Secp256k1.toHex(keys.privateKey),
    );
  }

  @override
  KeyMaterial generateFromSeed(
    Uint8List seed, {
    KeyType type = KeyType.secp256k1,
    bool compressed = false,
  }) {
    if (type.isPostQuantum) {
      final scheme = PostQuantum.schemeFor(type);
      // Refused rather than padded. A seed of the wrong length is a
      // different identity, and a library that accepts it returns a working
      // key that is not the one the caller asked for.
      if (seed.length != scheme.seedBytes) {
        throw ArgumentError(
          '${type.wire} needs a ${scheme.seedBytes}-byte seed, got ${seed.length}',
        );
      }
      final keys = scheme.fromSeed(seed);
      return KeyMaterial(
        publicKey: base64.encode(keys.publicKey),
        privateKey: base64.encode(keys.privateKey),
      );
    }
    _requireSecp256k1(type);
    final keys = Secp256k1.fromScalar(seed, compressed: compressed);
    return KeyMaterial(
      publicKey: Secp256k1.toHex(keys.publicKey),
      privateKey: Secp256k1.toHex(keys.privateKey),
    );
  }

  @override
  String sign(
    String data,
    String privateKey, {
    KeyType type = KeyType.secp256k1,
  }) {
    final message = Uint8List.fromList(utf8.encode(data));

    if (type.isPostQuantum) {
      final scheme = PostQuantum.schemeFor(type);
      final prv = _base64(privateKey, type, 'private');
      if (prv.length != scheme.privateKeyBytes) {
        throw ArgumentError(
          '${type.wire} private key should be '
          '${scheme.privateKeyBytes} bytes, got ${prv.length}'
          '${_strippedHint(type, prv.length, scheme.privateKeyBytes)}',
        );
      }
      return base64.encode(scheme.sign(message, prv));
    }

    if (PemBlock.looksLikePem(privateKey)) {
      // Signed with whatever the PEM actually holds, as the JavaScript SDK
      // does: a legacy identity's type string is not always accurate.
      return switch (PemPrivateKey.parse(privateKey)) {
        PemRsaPrivateKey(:final key) => base64.encode(
          RsaPkcs1.sign(message, key),
        ),
        PemEcPrivateKey(:final scalar) => base64.encode(
          Secp256k1.sign(message, scalar),
        ),
      };
    }

    if (type == KeyType.rsa) {
      throw ArgumentError('An rsa private key must be PEM');
    }
    final scalar = Secp256k1.fromHex(privateKey, 'private');
    if (scalar.length != Secp256k1.privateBytes) {
      throw ArgumentError(
        'secp256k1 private key should be 32 bytes, got '
        '${scalar.length}',
      );
    }
    return base64.encode(Secp256k1.sign(message, scalar));
  }

  @override
  bool verify(
    String data,
    String signature,
    String publicKey, {
    KeyType type = KeyType.secp256k1,
  }) {
    try {
      final message = Uint8List.fromList(utf8.encode(data));
      final sig = Uint8List.fromList(base64.decode(signature));

      if (type.isPostQuantum) {
        return PostQuantum.schemeFor(
          type,
        ).verify(message, sig, _base64(publicKey, type, 'public'));
      }

      if (PemBlock.looksLikePem(publicKey)) {
        return switch (PemPublicKey.parse(publicKey)) {
          PemRsaPublicKey(:final key) => RsaPkcs1.verify(message, sig, key),
          PemEcPublicKey(:final point) => Secp256k1.verify(message, sig, point),
        };
      }

      if (type == KeyType.rsa) return false;
      return Secp256k1.verify(
        message,
        sig,
        Secp256k1.fromHex(publicKey, 'public'),
      );
    } catch (_) {
      return false;
    }
  }

  /// The only non-post-quantum type this provider can MAKE is secp256k1.
  /// Anything else used to fall through to secp256k1 silently in older
  /// SDKs - asking for RSA returned an EC key - so it is refused instead.
  static void _requireSecp256k1(KeyType type) {
    if (type != KeyType.secp256k1) {
      throw ArgumentError(
        'Cannot generate a "${type.wire}" key - supported '
        'types are secp256k1, ml-dsa-65 and falcon-512',
      );
    }
  }

  /// BouncyCastle, among others, strips Falcon's 1-byte key header, which
  /// the ledger reports as 1220 "Signature Incorrect". Named here instead.
  static String _strippedHint(KeyType type, int actual, int expected) =>
      type == KeyType.falcon512 && actual == expected - 1
      ? ' - this looks like a key with its header byte stripped'
      : '';

  static Uint8List _base64(String value, KeyType type, String what) {
    if (value.startsWith('0x')) {
      throw ArgumentError(
        '${type.wire} $what key looks like hex - '
        'post-quantum keys are base64 of the raw bytes',
      );
    }
    try {
      return Uint8List.fromList(base64.decode(value));
    } on FormatException {
      throw ArgumentError('${type.wire} $what key is not valid base64');
    }
  }
}

/// Decoded, checked key bytes, for code that needs to validate a key before
/// it reaches a node (where a wrong length comes back as 1220).
abstract final class KeyCodec {
  /// Checks [publicKey] is well-formed for [type], throwing an
  /// [ArgumentError] naming the problem otherwise.
  static void checkPublicKey(KeyType type, String publicKey) {
    if (type.isPostQuantum) {
      final scheme = PostQuantum.schemeFor(type);
      final bytes = DefaultCryptoProvider._base64(publicKey, type, 'public');
      if (bytes.length != scheme.publicKeyBytes) {
        throw ArgumentError(
          '${type.wire} public key should be '
          '${scheme.publicKeyBytes} bytes, got ${bytes.length}'
          '${DefaultCryptoProvider._strippedHint(type, bytes.length, scheme.publicKeyBytes)}',
        );
      }
    } else if (type == KeyType.secp256k1 && !PemBlock.looksLikePem(publicKey)) {
      Secp256k1.checkPublic(Secp256k1.fromHex(publicKey, 'public'));
    } else {
      PemPublicKey.parse(publicKey);
    }
  }
}
