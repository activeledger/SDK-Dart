import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'der.dart';
import 'secp256k1.dart';

const _oidRsa = '1.2.840.113549.1.1.1';
const _oidEc = '1.2.840.10045.2.1';
const _oidSecp256k1 = '1.3.132.0.10';

/// A private key read from PEM: either RSA or a secp256k1 scalar.
sealed class PemPrivateKey {
  static PemPrivateKey parse(String pem) {
    final block = PemBlock.parse(pem);
    switch (block.label) {
      case 'RSA PRIVATE KEY':
        return PemRsaPrivateKey(_rsaPrivate(DerElement.parse(block.der)));
      case 'EC PRIVATE KEY':
        return PemEcPrivateKey(_sec1Private(DerElement.parse(block.der)));
      case 'PRIVATE KEY':
        // PKCS#8: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING }
        final parts = DerElement.parse(block.der).children;
        if (parts.length < 3) {
          throw const FormatException('PKCS#8: too few fields');
        }
        final algorithm = parts[1].children;
        final oid = algorithm.first.asOid;
        final inner = DerElement.parse(parts[2].content);
        if (oid == _oidRsa) return PemRsaPrivateKey(_rsaPrivate(inner));
        if (oid == _oidEc) {
          if (algorithm.length > 1 &&
              algorithm[1].tag == DerElement.oid &&
              algorithm[1].asOid != _oidSecp256k1) {
            throw FormatException(
              'EC key is on curve ${algorithm[1].asOid}, not secp256k1',
            );
          }
          return PemEcPrivateKey(_sec1Private(inner));
        }
        throw FormatException('Unsupported private key algorithm $oid');
      default:
        throw FormatException('Unsupported PEM block "${block.label}"');
    }
  }
}

final class PemRsaPrivateKey extends PemPrivateKey {
  PemRsaPrivateKey(this.key);
  final RSAPrivateKey key;
}

final class PemEcPrivateKey extends PemPrivateKey {
  PemEcPrivateKey(this.scalar);

  /// The 32-byte secp256k1 scalar.
  final Uint8List scalar;
}

/// A public key read from PEM: either RSA or a secp256k1 point.
sealed class PemPublicKey {
  static PemPublicKey parse(String pem) {
    final block = PemBlock.parse(pem);
    switch (block.label) {
      case 'RSA PUBLIC KEY':
        return PemRsaPublicKey(_rsaPublic(DerElement.parse(block.der)));
      case 'PUBLIC KEY':
        // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
        final parts = DerElement.parse(block.der).children;
        final algorithm = parts[0].children;
        final oid = algorithm.first.asOid;
        final bits = parts[1];
        if (bits.tag != DerElement.bitString || bits.content.isEmpty) {
          throw const FormatException('SPKI: expected BIT STRING');
        }
        final key = Uint8List.sublistView(bits.content, 1);
        if (oid == _oidRsa) {
          return PemRsaPublicKey(_rsaPublic(DerElement.parse(key)));
        }
        if (oid == _oidEc) {
          if (algorithm.length > 1 &&
              algorithm[1].tag == DerElement.oid &&
              algorithm[1].asOid != _oidSecp256k1) {
            throw FormatException(
              'EC key is on curve ${algorithm[1].asOid}, not secp256k1',
            );
          }
          return PemEcPublicKey(Uint8List.fromList(key));
        }
        throw FormatException('Unsupported public key algorithm $oid');
      default:
        throw FormatException('Unsupported PEM block "${block.label}"');
    }
  }
}

final class PemRsaPublicKey extends PemPublicKey {
  PemRsaPublicKey(this.key);
  final RSAPublicKey key;
}

final class PemEcPublicKey extends PemPublicKey {
  PemEcPublicKey(this.point);

  /// The SEC1-encoded secp256k1 point.
  final Uint8List point;
}

RSAPrivateKey _rsaPrivate(DerElement seq) {
  // RSAPrivateKey: version, n, e, d, p, q, dp, dq, qinv
  final f = seq.children;
  if (f.length < 6) throw const FormatException('PKCS#1: too few fields');
  return RSAPrivateKey(
    f[1].asUnsignedInt,
    f[3].asUnsignedInt,
    f[4].asUnsignedInt,
    f[5].asUnsignedInt,
  );
}

RSAPublicKey _rsaPublic(DerElement seq) {
  final f = seq.children;
  if (f.length != 2) throw const FormatException('RSAPublicKey: expected n, e');
  return RSAPublicKey(f[0].asUnsignedInt, f[1].asUnsignedInt);
}

Uint8List _sec1Private(DerElement seq) {
  // ECPrivateKey: version, OCTET STRING privateKey, [0] params, [1] public
  final f = seq.children;
  if (f.length < 2 || f[1].tag != DerElement.octetString) {
    throw const FormatException('SEC1: expected private key OCTET STRING');
  }
  for (final extra in f.skip(2)) {
    if (extra.tag == 0xa0) {
      final curve = extra.children.first;
      if (curve.tag == DerElement.oid && curve.asOid != _oidSecp256k1) {
        throw FormatException(
          'EC key is on curve ${curve.asOid}, not secp256k1',
        );
      }
    }
  }
  return bigIntToFixed(bytesToBigInt(f[1].content), Secp256k1.privateBytes);
}

/// RSASSA-PKCS1-v1_5 with SHA-256 - what `crypto.createSign("sha256")` does
/// with an RSA key, and so what the ledger verifies.
abstract final class RsaPkcs1 {
  static const _sha256DigestInfo = '0609608648016503040201';

  static Uint8List sign(Uint8List message, RSAPrivateKey key) {
    final signer = RSASigner(SHA256Digest(), _sha256DigestInfo)
      ..init(true, PrivateKeyParameter<RSAPrivateKey>(key));
    return signer.generateSignature(message).bytes;
  }

  static bool verify(Uint8List message, Uint8List signature, RSAPublicKey key) {
    try {
      final verifier = RSASigner(SHA256Digest(), _sha256DigestInfo)
        ..init(false, PublicKeyParameter<RSAPublicKey>(key));
      return verifier.verifySignature(message, RSASignature(signature));
    } catch (_) {
      return false;
    }
  }
}
