import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'der.dart';
import 'random.dart';

/// secp256k1, encoded the way Activeledger stores it.
///
/// Kept apart from the post-quantum paths because almost nothing is shared.
/// Post-quantum keys are raw bytes in base64; these are hex with a `0x`
/// prefix. Post-quantum signatures are raw blobs; these are variable-length
/// DER. Reusing a base64 path for a hex key produces material the ledger
/// rejects as 1220 "Signature Incorrect" while saying nothing else.
abstract final class Secp256k1 {
  /// 33 compressed, 65 uncompressed. The ledger accepts both.
  static const int publicCompressedBytes = 33;
  static const int publicUncompressedBytes = 65;
  static const int privateBytes = 32;

  static final ECDomainParameters domain = ECCurve_secp256k1();

  /// The curve order n.
  static BigInt get order => domain.n;

  static final BigInt _halfOrder = domain.n >> 1;

  static final RegExp _hex = RegExp(r'^[0-9a-fA-F]*$');

  /// A fresh key pair as (public point, 32-byte private scalar).
  static ({Uint8List publicKey, Uint8List privateKey}) generate({
    bool compressed = false,
  }) {
    while (true) {
      final seed = secureRandomBytes(privateBytes);
      if (isValidScalar(seed)) {
        return fromScalar(seed, compressed: compressed);
      }
    }
  }

  /// The key pair for a 32-byte private scalar.
  ///
  /// Refused, not reduced mod n, when the scalar is 0 or >= n: reducing
  /// produces a perfectly functional key belonging to a different identity,
  /// and nothing downstream ever reports a problem.
  static ({Uint8List publicKey, Uint8List privateKey}) fromScalar(
    Uint8List scalar, {
    bool compressed = false,
  }) {
    if (scalar.length != privateBytes) {
      throw ArgumentError(
        'secp256k1 needs a 32-byte seed, got ${scalar.length}',
      );
    }
    if (!isValidScalar(scalar)) {
      throw ArgumentError(
        'seed is not a valid secp256k1 private key - the '
        'scalar must be in [1, n-1]',
      );
    }
    final d = bytesToBigInt(scalar);
    final point = (domain.G * d)!;
    return (
      publicKey: point.getEncoded(compressed),
      // The scalar as given, never re-derived from the BigInt, which would
      // drop leading zero bytes (about one key in 400).
      privateKey: Uint8List.fromList(scalar),
    );
  }

  /// Whether [scalar] is a usable private key: in [1, n-1].
  static bool isValidScalar(Uint8List scalar) {
    final d = bytesToBigInt(scalar);
    return d > BigInt.zero && d < domain.n;
  }

  /// Signs with a deterministic k (RFC 6979) and S normalised low.
  ///
  /// **Deterministic k** makes signatures reproducible, so exact expected
  /// bytes can be published as cross-language vectors - and this signer is
  /// checked byte for byte against them.
  ///
  /// **Low S** is not for the ledger, which verifies through OpenSSL and
  /// accepts either. It is for everything else: `@noble/curves`,
  /// libsecp256k1 and Rust's `k256` all reject high-S by default.
  static Uint8List sign(Uint8List message, Uint8List privateScalar) {
    final signer = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64))
      ..init(
        true,
        PrivateKeyParameter<ECPrivateKey>(
          ECPrivateKey(bytesToBigInt(privateScalar), domain),
        ),
      );
    final signature = (signer.generateSignature(message) as ECSignature)
        .normalize(domain);
    return encodeDer(signature.r, signature.s);
  }

  /// Verifies a DER signature, accepting HIGH-S as well as low.
  ///
  /// The ledger produces high-S signatures freely, so rejecting them would
  /// reject roughly half of everything it makes - an intermittent failure
  /// that looks like anything but a configuration flag.
  static bool verify(
    Uint8List message,
    Uint8List signature,
    Uint8List publicPoint,
  ) {
    try {
      final point = domain.curve.decodePoint(publicPoint);
      if (point == null || point.isInfinity) return false;
      final (r, s) = decodeDer(signature);
      if (r <= BigInt.zero || r >= domain.n) return false;
      if (s <= BigInt.zero || s >= domain.n) return false;
      final verifier = ECDSASigner(SHA256Digest())
        ..init(
          false,
          PublicKeyParameter<ECPublicKey>(ECPublicKey(point, domain)),
        );
      return verifier.verifySignature(message, ECSignature(r, s));
    } catch (_) {
      return false;
    }
  }

  /// Whether a DER signature's S is in the upper half of the curve order.
  ///
  /// Everything this SDK emits is low-S; this is for signatures that arrived
  /// from elsewhere, before handing them to a strict verifier.
  static bool isHighS(Uint8List signature) =>
      decodeDer(signature).$2 > _halfOrder;

  /// Folds S into the lower half of the curve order.
  static BigInt lowS(BigInt s) => s > _halfOrder ? domain.n - s : s;

  /// SEQUENCE { INTEGER r, INTEGER s }.
  static Uint8List encodeDer(BigInt r, BigInt s) =>
      derSequence([derInteger(r), derInteger(s)]);

  /// Parses SEQUENCE { INTEGER r, INTEGER s }.
  static (BigInt, BigInt) decodeDer(Uint8List signature) {
    final seq = DerElement.parse(signature);
    if (seq.tag != DerElement.sequence) {
      throw const FormatException('ECDSA signature is not a DER SEQUENCE');
    }
    final parts = seq.children;
    if (parts.length != 2) {
      throw FormatException(
        'DER signature has ${parts.length} components, expected 2',
      );
    }
    return (parts[0].asUnsignedInt, parts[1].asUnsignedInt);
  }

  /// Checks a public key's length and SEC1 prefix, and that it is on the
  /// curve.
  static void checkPublic(Uint8List bytes) {
    if (bytes.length != publicCompressedBytes &&
        bytes.length != publicUncompressedBytes) {
      throw ArgumentError(
        'secp256k1 public key is ${bytes.length} bytes, '
        'expected $publicCompressedBytes (compressed) or '
        '$publicUncompressedBytes (uncompressed)',
      );
    }
    final prefix = bytes[0];
    final ok = bytes.length == publicCompressedBytes
        ? prefix == 0x02 || prefix == 0x03
        : prefix == 0x04;
    if (!ok) {
      throw ArgumentError(
        'secp256k1 public key starts with 0x'
        '${prefix.toRadixString(16).padLeft(2, '0')}, which does not match '
        'its length of ${bytes.length} bytes (expected 0x02/0x03 for 33, '
        '0x04 for 65)',
      );
    }
    try {
      domain.curve.decodePoint(bytes);
    } catch (_) {
      throw ArgumentError('secp256k1 public key is not a point on the curve');
    }
  }

  /// Bytes as the ledger stores secp256k1 keys: `0x` + lowercase hex.
  static String toHex(Uint8List bytes) {
    final out = StringBuffer('0x');
    for (final b in bytes) {
      out.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return out.toString();
  }

  /// Decodes an `0x`-prefixed hex key.
  ///
  /// The prefix is required rather than tolerated: it is part of what the
  /// ledger stores, and hex without it can decode as base64 into
  /// plausible-looking bytes of the wrong length.
  static Uint8List fromHex(String value, String what) {
    if (!value.startsWith('0x')) {
      throw ArgumentError(
        "secp256k1 $what key must start with '0x' - that "
        'prefix is part of what the ledger stores, not decoration. '
        'Post-quantum keys are base64; these are not.',
      );
    }
    final body = value.substring(2);
    if (body.length.isOdd) {
      throw ArgumentError(
        'secp256k1 $what key has an odd number of hex '
        'digits (${body.length})',
      );
    }
    if (!_hex.hasMatch(body)) {
      throw ArgumentError('secp256k1 $what key is not valid hex');
    }
    final out = Uint8List(body.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(body.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return out;
  }
}
