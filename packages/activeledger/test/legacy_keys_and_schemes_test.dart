import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:activeledger/activeledger.dart';
import 'package:activeledger/src/crypto/der.dart';
import 'package:activeledger/src/crypto/pem_keys.dart';
import 'package:test/test.dart';

/// Malformed and unusual PEM keys, the RSA verifier, key validation and the
/// post-quantum registry. No Falcon: a real Falcon key would swap liboqs's
/// process-wide RNG callback, which falcon_test.dart owns.
Uint8List b(List<int> v) => Uint8List.fromList(v);

Uint8List oid(List<int> content) =>
    b([DerElement.oid, content.length, ...content]);

Uint8List octets(List<int> content) =>
    b([DerElement.octetString, ...derLength(content.length), ...content]);

Uint8List bitString(List<int> content) =>
    b([DerElement.bitString, ...derLength(content.length + 1), 0, ...content]);

String pem(String label, Uint8List der) {
  final body = base64.encode(der);
  final lines = [
    for (var i = 0; i < body.length; i += 64)
      body.substring(i, i + 64 > body.length ? body.length : i + 64),
  ];
  return '-----BEGIN $label-----\n${lines.join('\n')}\n-----END $label-----\n';
}

// Content bytes of the OIDs involved.
final oidRsa = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
final oidEc = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
final oidSecp256k1 = [0x2b, 0x81, 0x04, 0x00, 0x0a];
final oidPrime256v1 = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
final oidEd25519 = [0x2b, 0x65, 0x70];

final zero = derInteger(BigInt.zero);

/// ECPrivateKey { version 1, OCTET STRING scalar [, [0] curve] }.
Uint8List sec1(Uint8List scalar, {List<int>? curve}) => derSequence([
  derInteger(BigInt.one),
  octets(scalar),
  if (curve != null) b([0xa0, curve.length + 2, 0x06, curve.length, ...curve]),
]);

Uint8List pkcs8(Uint8List algorithm, Uint8List inner) =>
    derSequence([zero, algorithm, octets(inner)]);

void main() {
  final fixture =
      (jsonDecode(File('test/fixtures/pem-keys.json').readAsStringSync())
              as Map)
          .cast<String, Object?>();
  final message = fixture['message']! as String;
  final rsa = (fixture['rsa']! as Map).cast<String, String>();
  final ec = (fixture['secp256k1']! as Map).cast<String, String>();
  const crypto = DefaultCryptoProvider();
  final scalar = Secp256k1.fromHex(ec['hexPrivate']!, 'private');

  Matcher formatError(String text) => throwsA(
    isA<FormatException>().having((e) => e.message, 'message', contains(text)),
  );

  group('PemPrivateKey.parse', () {
    test('reads RSA from PKCS#1 and PKCS#8 into the same key', () {
      final a = PemPrivateKey.parse(rsa['pkcs1']!) as PemRsaPrivateKey;
      final c = PemPrivateKey.parse(rsa['pkcs8']!) as PemRsaPrivateKey;
      expect(a.key.modulus, c.key.modulus);
      expect(a.key.privateExponent, c.key.privateExponent);
    });

    test('reads secp256k1 from SEC1 and PKCS#8 into the stored scalar', () {
      for (final text in [ec['sec1']!, ec['pkcs8']!]) {
        final key = PemPrivateKey.parse(text) as PemEcPrivateKey;
        expect(key.scalar, scalar);
      }
    });

    test('a SEC1 scalar shorter than 32 bytes is left-padded', () {
      final key =
          PemPrivateKey.parse(pem('EC PRIVATE KEY', sec1(b([1, 2]))))
              as PemEcPrivateKey;
      expect(key.scalar.length, 32);
      expect(key.scalar.sublist(30), [1, 2]);
      expect(key.scalar.sublist(0, 30), everyElement(0));
    });

    test('SEC1 naming secp256k1 in its parameters is accepted', () {
      final text = pem('EC PRIVATE KEY', sec1(scalar, curve: oidSecp256k1));
      expect((PemPrivateKey.parse(text) as PemEcPrivateKey).scalar, scalar);
    });

    test('SEC1 naming another curve is refused', () {
      final text = pem('EC PRIVATE KEY', sec1(scalar, curve: oidPrime256v1));
      expect(
        () => PemPrivateKey.parse(text),
        formatError('1.2.840.10045.3.1.7, not secp256k1'),
      );
    });

    test('SEC1 without the private key OCTET STRING is refused', () {
      final text = pem('EC PRIVATE KEY', derSequence([derInteger(BigInt.one)]));
      expect(() => PemPrivateKey.parse(text), formatError('SEC1'));
      final wrong = pem(
        'EC PRIVATE KEY',
        derSequence([derInteger(BigInt.one), derInteger(BigInt.one)]),
      );
      expect(() => PemPrivateKey.parse(wrong), formatError('SEC1'));
    });

    test('PKCS#1 with too few fields is refused', () {
      final text = pem(
        'RSA PRIVATE KEY',
        derSequence([zero, derInteger(BigInt.from(15))]),
      );
      expect(() => PemPrivateKey.parse(text), formatError('too few fields'));
    });

    test('PKCS#8 EC key on another curve is refused', () {
      final algorithm = derSequence([oid(oidEc), oid(oidPrime256v1)]);
      final text = pem('PRIVATE KEY', pkcs8(algorithm, sec1(scalar)));
      expect(
        () => PemPrivateKey.parse(text),
        formatError('1.2.840.10045.3.1.7, not secp256k1'),
      );
    });

    test('PKCS#8 EC key without a curve parameter is taken as secp256k1', () {
      final algorithm = derSequence([oid(oidEc)]);
      final text = pem('PRIVATE KEY', pkcs8(algorithm, sec1(scalar)));
      expect((PemPrivateKey.parse(text) as PemEcPrivateKey).scalar, scalar);
    });

    test('PKCS#8 of an unsupported algorithm names the OID', () {
      final algorithm = derSequence([oid(oidEd25519)]);
      final text = pem('PRIVATE KEY', pkcs8(algorithm, octets(Uint8List(32))));
      expect(
        () => PemPrivateKey.parse(text),
        formatError('Unsupported private key algorithm 1.3.101.112'),
      );
    });

    test('PKCS#8 with too few fields is refused', () {
      final text = pem('PRIVATE KEY', derSequence([zero, derSequence([])]));
      expect(() => PemPrivateKey.parse(text), formatError('PKCS#8'));
    });

    test('an unknown PEM label is refused by name', () {
      expect(
        () => PemPrivateKey.parse(pem('CERTIFICATE', b([1]))),
        formatError('Unsupported PEM block "CERTIFICATE"'),
      );
    });
  });

  group('PemPublicKey.parse', () {
    Uint8List spki(List<int> algorithm, List<int> key) => derSequence([
      derSequence([oid(algorithm)]),
      bitString(key),
    ]);

    test('reads RSA from SPKI and PKCS#1 into the same key', () {
      final a = PemPublicKey.parse(rsa['spki']!) as PemRsaPublicKey;
      final c = PemPublicKey.parse(rsa['pkcs1Public']!) as PemRsaPublicKey;
      expect(a.key.modulus, c.key.modulus);
      expect(a.key.exponent, BigInt.from(65537));
    });

    test('reads the secp256k1 point from SPKI', () {
      final key = PemPublicKey.parse(ec['spki']!) as PemEcPublicKey;
      expect(key.point, Secp256k1.fromHex(ec['hexPublic']!, 'public'));
    });

    test('an EC SPKI on another curve is refused', () {
      final point = Secp256k1.fromHex(ec['hexPublic']!, 'public');
      final text = pem(
        'PUBLIC KEY',
        derSequence([
          derSequence([oid(oidEc), oid(oidPrime256v1)]),
          bitString(point),
        ]),
      );
      expect(
        () => PemPublicKey.parse(text),
        formatError('1.2.840.10045.3.1.7, not secp256k1'),
      );
    });

    test('an SPKI of an unsupported algorithm names the OID', () {
      final text = pem(
        'PUBLIC KEY',
        derSequence([
          derSequence([oid(oidEd25519)]),
          bitString(Uint8List(32)),
        ]),
      );
      expect(
        () => PemPublicKey.parse(text),
        formatError('Unsupported public key algorithm 1.3.101.112'),
      );
    });

    test('an SPKI whose key is not a BIT STRING, or is empty, is refused', () {
      final notBits = pem(
        'PUBLIC KEY',
        derSequence([
          derSequence([oid(oidEc)]),
          octets(Uint8List(33)),
        ]),
      );
      expect(() => PemPublicKey.parse(notBits), formatError('BIT STRING'));
      final empty = pem(
        'PUBLIC KEY',
        derSequence([
          derSequence([oid(oidEc)]),
          b([DerElement.bitString, 0]),
        ]),
      );
      expect(() => PemPublicKey.parse(empty), formatError('BIT STRING'));
    });

    test('PKCS#1 public key must have exactly modulus and exponent', () {
      final text = pem(
        'RSA PUBLIC KEY',
        derSequence([
          derInteger(BigInt.from(15)),
          derInteger(BigInt.from(3)),
          derInteger(BigInt.from(1)),
        ]),
      );
      expect(() => PemPublicKey.parse(text), formatError('expected n, e'));
    });

    test('an unknown PEM label is refused by name', () {
      expect(
        () => PemPublicKey.parse(pem('EC PUBLIC KEY', b([1]))),
        formatError('Unsupported PEM block "EC PUBLIC KEY"'),
      );
    });

    test('an EC SPKI with no curve parameter is taken as secp256k1', () {
      final point = Secp256k1.fromHex(ec['hexPublic']!, 'public');
      final built = pem('PUBLIC KEY', spki(oidEc, point));
      expect((PemPublicKey.parse(built) as PemEcPublicKey).point, point);
    });
  });

  group('RsaPkcs1.verify', () {
    final key = (PemPublicKey.parse(rsa['spki']!) as PemRsaPublicKey).key;
    final data = b(utf8.encode(message));
    final signature = b(base64.decode(rsa['signature']!));

    test('accepts the node:crypto signature', () {
      expect(RsaPkcs1.verify(data, signature, key), isTrue);
    });

    test('rejects a changed message and a changed signature', () {
      expect(RsaPkcs1.verify(b([...data, 0x20]), signature, key), isFalse);
      final bad = b(signature)..[10] ^= 0x01;
      expect(RsaPkcs1.verify(data, bad, key), isFalse);
    });

    test('returns false for a signature of the wrong length', () {
      expect(RsaPkcs1.verify(data, signature.sublist(1), key), isFalse);
      expect(RsaPkcs1.verify(data, b([]), key), isFalse);
    });
  });

  group('DefaultCryptoProvider with legacy keys', () {
    test('signs with what the PEM holds, whatever type says', () {
      expect(
        crypto.sign(message, rsa['pkcs8']!, type: KeyType.secp256k1),
        rsa['signature'],
      );
      final viaEcPem = crypto.sign(message, ec['pkcs8']!, type: KeyType.rsa);
      expect(crypto.verify(message, viaEcPem, ec['hexPublic']!), isTrue);
    });

    test('verifies against a PEM public key whatever type says', () {
      expect(crypto.verify(message, rsa['signature']!, rsa['spki']!), isTrue);
      final sig = crypto.sign(message, ec['hexPrivate']!);
      expect(crypto.verify(message, sig, ec['spki']!), isTrue);
      expect(
        crypto.verify(message, sig, ec['spki']!, type: KeyType.rsa),
        isTrue,
      );
    });

    test('an rsa verify with a non-PEM key is false, not an error', () {
      expect(
        crypto.verify(
          message,
          rsa['signature']!,
          ec['hexPublic']!,
          type: KeyType.rsa,
        ),
        isFalse,
      );
    });

    test('verify is false for a signature that is not base64', () {
      expect(crypto.verify(message, '***', ec['hexPublic']!), isFalse);
    });

    test('a secp256k1 private key of the wrong length is refused', () {
      expect(
        () => crypto.sign(message, '0x${'ab' * 31}'),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('should be 32 bytes, got 31'),
          ),
        ),
      );
      expect(() => crypto.sign(message, '0x${'ab' * 33}'), throwsArgumentError);
    });
  });

  group('KeyCodec.checkPublicKey', () {
    // Fixed bytes, not a generated key: a random key's base64 starts with
    // "0x" about 1 time in 4096, which once failed CI.
    final mlPublic = base64.encode(Uint8List(1952)..fillRange(0, 1952, 7));

    Matcher argError(String text) => throwsA(
      isA<ArgumentError>().having((e) => e.message, 'message', contains(text)),
    );

    test('accepts a well-formed ml-dsa-65 key', () {
      KeyCodec.checkPublicKey(KeyType.mlDsa65, mlPublic);
    });

    test('accepts a base64 ml-dsa-65 key that begins with 0x', () {
      final bytes = Uint8List(1952)
        ..[0] = 0xD3
        ..[1] = 0x10;
      final key = base64.encode(bytes);
      expect(key, startsWith('0x'));
      KeyCodec.checkPublicKey(KeyType.mlDsa65, key);
    });

    test('names a wrong ml-dsa-65 length', () {
      expect(
        () => KeyCodec.checkPublicKey(
          KeyType.mlDsa65,
          base64.encode(Uint8List(100)),
        ),
        argError('should be 1952 bytes, got 100'),
      );
    });

    test('refuses hex and bad base64 for a post-quantum key', () {
      expect(
        () => KeyCodec.checkPublicKey(KeyType.mlDsa65, '0xabcd'),
        argError('looks like hex'),
      );
      expect(
        () => KeyCodec.checkPublicKey(KeyType.mlDsa65, '***'),
        argError('not valid base64'),
      );
    });

    test('falcon-512 without the add-on is unavailable, not a bad key', () {
      expect(
        () => KeyCodec.checkPublicKey(KeyType.falcon512, 'AAAA'),
        throwsA(isA<KeyTypeUnavailableException>()),
      );
    });

    test('checks secp256k1 hex, and accepts a PEM public key', () {
      KeyCodec.checkPublicKey(KeyType.secp256k1, ec['hexPublic']!);
      KeyCodec.checkPublicKey(KeyType.secp256k1, ec['spki']!);
      expect(
        () => KeyCodec.checkPublicKey(KeyType.secp256k1, 'abcd'),
        argError("must start with '0x'"),
      );
      expect(
        () => KeyCodec.checkPublicKey(KeyType.secp256k1, '0x04ab'),
        argError('is 2 bytes'),
      );
    });

    test('rsa takes PEM only', () {
      KeyCodec.checkPublicKey(KeyType.rsa, rsa['spki']!);
      expect(
        () => KeyCodec.checkPublicKey(KeyType.rsa, '0x0102'),
        throwsFormatException,
      );
    });
  });

  group('MlDsa65Scheme', () {
    final scheme = MlDsa65Scheme();
    final pair = scheme.fromSeed(Uint8List.fromList(List.filled(32, 7)));
    final data = b(utf8.encode('payload'));

    test('reports FIPS 204 ML-DSA-65 sizes', () {
      expect(scheme.type, KeyType.mlDsa65);
      expect(scheme.publicKeyBytes, 1952);
      expect(scheme.privateKeyBytes, 4032);
      expect(scheme.seedBytes, 32);
      expect(pair.publicKey.length, 1952);
      expect(pair.privateKey.length, 4032);
    });

    test('the same seed gives the same key, a different seed another', () {
      final again = scheme.fromSeed(Uint8List.fromList(List.filled(32, 7)));
      expect(again.publicKey, pair.publicKey);
      final other = scheme.fromSeed(Uint8List.fromList(List.filled(32, 8)));
      expect(other.publicKey, isNot(pair.publicKey));
    });

    test('generate makes a usable random key', () {
      final a = scheme.generate();
      final c = scheme.generate();
      expect(a.publicKey, isNot(c.publicKey));
      final sig = scheme.sign(data, a.privateKey);
      expect(scheme.verify(data, sig, a.publicKey), isTrue);
    });

    test('fromSeed refuses any other seed length', () {
      for (final length in [0, 31, 33]) {
        expect(
          () => scheme.fromSeed(Uint8List(length)),
          throwsA(
            isA<ArgumentError>().having(
              (e) => e.message,
              'message',
              contains('needs a 32-byte seed, got $length'),
            ),
          ),
        );
      }
    });

    test('sign refuses a private key of the wrong length', () {
      expect(
        () => scheme.sign(data, pair.privateKey.sublist(1)),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('should be 4032 bytes, got 4031'),
          ),
        ),
      );
    });

    test('signing is hedged: two signatures differ and both verify', () {
      final one = scheme.sign(data, pair.privateKey);
      final two = scheme.sign(data, pair.privateKey);
      expect(one, isNot(two));
      expect(scheme.verify(data, one, pair.publicKey), isTrue);
      expect(scheme.verify(data, two, pair.publicKey), isTrue);
    });

    test('verify is false, not an error, for bad input', () {
      final sig = scheme.sign(data, pair.privateKey);
      expect(scheme.verify(b([...data, 0]), sig, pair.publicKey), isFalse);
      expect(scheme.verify(data, sig, pair.publicKey.sublist(1)), isFalse);
      expect(scheme.verify(data, sig.sublist(1), pair.publicKey), isFalse);
      expect(scheme.verify(data, b([]), pair.publicKey), isFalse);
      final other = scheme.fromSeed(Uint8List(32));
      expect(scheme.verify(data, sig, other.publicKey), isFalse);
    });
  });

  group('PostQuantum registry', () {
    tearDown(() {
      PostQuantum.unregister(KeyType.falcon512);
      PostQuantum.unregister(KeyType.mlDsa65);
    });

    test('ml-dsa-65 is built in; falcon-512 and classical types are not', () {
      expect(PostQuantum.isAvailable(KeyType.mlDsa65), isTrue);
      expect(PostQuantum.isAvailable(KeyType.falcon512), isFalse);
      expect(PostQuantum.isAvailable(KeyType.secp256k1), isFalse);
    });

    test('schemeFor says what is missing', () {
      expect(
        () => PostQuantum.schemeFor(KeyType.falcon512),
        throwsA(
          isA<KeyTypeUnavailableException>().having(
            (e) => e.message,
            'message',
            contains('ActiveledgerFalcon.enable()'),
          ),
        ),
      );
      expect(
        () => PostQuantum.schemeFor(KeyType.rsa),
        throwsA(
          isA<KeyTypeUnavailableException>().having(
            (e) => e.message,
            'message',
            contains('rsa is not a post-quantum type'),
          ),
        ),
      );
    });

    test('register refuses a scheme for a classical key type', () {
      expect(
        () => PostQuantum.register(_FakeScheme(KeyType.secp256k1)),
        throwsArgumentError,
      );
      expect(PostQuantum.isAvailable(KeyType.secp256k1), isFalse);
    });

    test('a registered scheme is used, and unregistering removes it', () {
      final fake = _FakeScheme(KeyType.falcon512);
      PostQuantum.register(fake);
      expect(PostQuantum.isAvailable(KeyType.falcon512), isTrue);
      expect(identical(PostQuantum.schemeFor(KeyType.falcon512), fake), isTrue);

      PostQuantum.unregister(KeyType.falcon512);
      expect(PostQuantum.isAvailable(KeyType.falcon512), isFalse);
    });

    test('a replaced ml-dsa-65 scheme is restored by unregister', () {
      final fake = _FakeScheme(KeyType.mlDsa65);
      PostQuantum.register(fake);
      expect(identical(PostQuantum.schemeFor(KeyType.mlDsa65), fake), isTrue);

      PostQuantum.unregister(KeyType.mlDsa65);
      final restored = PostQuantum.schemeFor(KeyType.mlDsa65);
      expect(restored, isA<MlDsa65Scheme>());
      expect(identical(restored, fake), isFalse);
    });

    test('the crypto provider signs through a registered scheme', () {
      final fake = _FakeScheme(KeyType.mlDsa65);
      PostQuantum.register(fake);
      final key = base64.encode(Uint8List(fake.privateKeyBytes));
      final sig = crypto.sign('data', key, type: KeyType.mlDsa65);
      expect(base64.decode(sig), [0xfa, 0xce]);
      expect(fake.signed, 1);
    });
  });
}

/// A stand-in scheme that signs everything as 0xface and counts calls.
class _FakeScheme implements PostQuantumScheme {
  _FakeScheme(this.type);

  @override
  final KeyType type;

  int signed = 0;

  @override
  int get publicKeyBytes => 4;

  @override
  int get privateKeyBytes => 4;

  @override
  int get seedBytes => 4;

  @override
  ({Uint8List publicKey, Uint8List privateKey}) generate() =>
      (publicKey: Uint8List(4), privateKey: Uint8List(4));

  @override
  ({Uint8List publicKey, Uint8List privateKey}) fromSeed(Uint8List seed) =>
      generate();

  @override
  Uint8List sign(Uint8List message, Uint8List privateKey) {
    signed++;
    return Uint8List.fromList([0xfa, 0xce]);
  }

  @override
  bool verify(Uint8List message, Uint8List signature, Uint8List publicKey) =>
      signature.length == 2;
}
