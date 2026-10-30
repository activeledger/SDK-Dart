import 'dart:convert';
import 'dart:typed_data';

import 'package:activeledger/activeledger.dart';
import 'package:activeledger/src/crypto/der.dart';
import 'package:test/test.dart';

/// secp256k1 key checks, hex handling and signature edge cases, against
/// constants from SEC 2 rather than values the code derived itself.
Uint8List hexBytes(String hex) => Uint8List.fromList([
  for (var i = 0; i < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
]);

String toHex(List<int> b) =>
    b.map((v) => v.toRadixString(16).padLeft(2, '0')).join();

// The generator point G, and the group order n.
const gX = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const gY = '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
final n = BigInt.parse(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  radix: 16,
);

Uint8List scalar(BigInt v) => bigIntToFixed(v, 32);

void main() {
  final message = Uint8List.fromList(utf8.encode('{"hello":"world"}'));
  final pair = Secp256k1.fromScalar(scalar(BigInt.from(0x1234567)));

  test('the curve order is the SEC 2 value', () {
    expect(Secp256k1.order, n);
  });

  group('fromScalar', () {
    test('1 gives the generator point, compressed and uncompressed', () {
      final one = scalar(BigInt.one);
      expect(toHex(Secp256k1.fromScalar(one).publicKey), '04$gX$gY');
      expect(
        toHex(Secp256k1.fromScalar(one, compressed: true).publicKey),
        '02$gX',
      );
    });

    test('n-1 is the largest accepted scalar and negates G', () {
      final key = Secp256k1.fromScalar(
        scalar(n - BigInt.one),
        compressed: true,
      );
      // -G has the same x and the opposite y parity (G's y is even).
      expect(toHex(key.publicKey), '03$gX');
    });

    test('0, n and above, and wrong lengths are refused', () {
      expect(
        () => Secp256k1.fromScalar(scalar(BigInt.zero)),
        throwsArgumentError,
      );
      expect(() => Secp256k1.fromScalar(scalar(n)), throwsArgumentError);
      expect(
        () => Secp256k1.fromScalar(Uint8List(31)..[30] = 1),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('32-byte'),
          ),
        ),
      );
      expect(() => Secp256k1.fromScalar(Uint8List(33)), throwsArgumentError);
    });

    test('keeps leading zero bytes of the scalar', () {
      final s = scalar(BigInt.from(7));
      expect(Secp256k1.fromScalar(s).privateKey, s);
      expect(Secp256k1.fromScalar(s).privateKey.length, 32);
    });
  });

  test('isValidScalar draws the line at [1, n-1]', () {
    expect(Secp256k1.isValidScalar(scalar(BigInt.zero)), isFalse);
    expect(Secp256k1.isValidScalar(scalar(BigInt.one)), isTrue);
    expect(Secp256k1.isValidScalar(scalar(n - BigInt.one)), isTrue);
    expect(Secp256k1.isValidScalar(scalar(n)), isFalse);
  });

  test('generate yields a 32-byte scalar matching its public key', () {
    final key = Secp256k1.generate(compressed: true);
    expect(key.privateKey.length, 32);
    expect(key.publicKey.length, Secp256k1.publicCompressedBytes);
    expect(
      Secp256k1.fromScalar(key.privateKey, compressed: true).publicKey,
      key.publicKey,
    );
  });

  group('checkPublic', () {
    test('accepts G in both encodings', () {
      Secp256k1.checkPublic(hexBytes('02$gX'));
      Secp256k1.checkPublic(hexBytes('04$gX$gY'));
    });

    test('refuses lengths other than 33 and 65', () {
      for (final length in [0, 32, 34, 64, 66]) {
        expect(
          () => Secp256k1.checkPublic(Uint8List(length)),
          throwsA(
            isA<ArgumentError>().having(
              (e) => e.message,
              'message',
              contains('is $length bytes'),
            ),
          ),
        );
      }
    });

    test('refuses a prefix that does not match the length', () {
      expect(
        () => Secp256k1.checkPublic(hexBytes('04$gX')),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('starts with 0x04'),
          ),
        ),
      );
      expect(
        () => Secp256k1.checkPublic(hexBytes('02$gX$gY')),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('starts with 0x02'),
          ),
        ),
      );
    });

    test('refuses a compressed x with no point on the curve', () {
      // x = 5: x^3 + 7 = 132 is not a square mod p, so no y exists.
      final x = '5'.padLeft(64, '0');
      expect(
        () => Secp256k1.checkPublic(hexBytes('02$x')),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('not a point on the curve'),
          ),
        ),
      );
    });
  });

  group('off-curve public keys', () {
    // The field prime p.
    final p = BigInt.parse(
      'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
      radix: 16,
    );
    String h(BigInt v) => v.toRadixString(16).padLeft(64, '0');
    final y = BigInt.parse(gY, radix: 16);
    final hexKey = Secp256k1.toHex;

    void refused(String hex) {
      final bytes = hexBytes(hex);
      expect(() => Secp256k1.checkPublic(bytes), throwsArgumentError);
      expect(
        () => KeyCodec.checkPublicKey(KeyType.secp256k1, hexKey(bytes)),
        throwsArgumentError,
      );
      expect(
        Secp256k1.verify(
          message,
          Secp256k1.sign(message, scalar(n - BigInt.one)),
          bytes,
        ),
        isFalse,
      );
    }

    test('refuses an uncompressed point off the curve', () {
      refused('04$gX${h(y + BigInt.one)}');
    });

    test('refuses coordinates at or above p', () {
      // x = p + 1 reduces to x = 1, which does have points on the curve.
      const y1 =
          '4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee';
      refused('04${h(p + BigInt.one)}$y1');
      refused('02${h(p + BigInt.one)}');
      refused('03${h(p + BigInt.one)}');
      refused('04$gX${h(p)}');
      refused('04${h(p)}${h(p)}');
    });

    test('refuses point-at-infinity and all-zero encodings', () {
      refused('04${'00' * 64}');
      refused('02${'00' * 32}');
      refused('00${'00' * 64}');
      refused('00${'00' * 32}');
    });

    test('still accepts valid compressed and uncompressed keys', () {
      for (final compressed in [true, false]) {
        final key = Secp256k1.fromScalar(
          scalar(BigInt.from(0x1234567)),
          compressed: compressed,
        );
        Secp256k1.checkPublic(key.publicKey);
        KeyCodec.checkPublicKey(KeyType.secp256k1, hexKey(key.publicKey));
        final sig = Secp256k1.sign(message, key.privateKey);
        expect(Secp256k1.verify(message, sig, key.publicKey), isTrue);
      }
    });
  });

  group('hex encoding', () {
    test('toHex writes 0x, lowercase, two digits per byte', () {
      expect(
        Secp256k1.toHex(Uint8List.fromList([0, 1, 0xab, 0xff])),
        '0x0001abff',
      );
      expect(Secp256k1.toHex(Uint8List(0)), '0x');
    });

    test('fromHex reads either case and round-trips', () {
      expect(Secp256k1.fromHex('0x00ABcd', 'public'), [0x00, 0xab, 0xcd]);
      expect(Secp256k1.fromHex('0x', 'public'), isEmpty);
      expect(Secp256k1.toHex(Secp256k1.fromHex('0x01ff', 'x')), '0x01ff');
    });

    test('a missing 0x prefix names the key kind', () {
      expect(
        () => Secp256k1.fromHex('abcd', 'private'),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            allOf(contains('private key must start with'), contains('0x')),
          ),
        ),
      );
    });

    test('an odd digit count and non-hex digits are refused', () {
      expect(
        () => Secp256k1.fromHex('0xabc', 'public'),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('odd number'),
          ),
        ),
      );
      expect(
        () => Secp256k1.fromHex('0xzz', 'public'),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('not valid hex'),
          ),
        ),
      );
    });
  });

  group('DER signatures', () {
    test('encodeDer pads a high bit and decodeDer reads it back', () {
      final der = Secp256k1.encodeDer(BigInt.from(0x80), BigInt.one);
      expect(der, [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01]);
      final (r, s) = Secp256k1.decodeDer(der);
      expect(r, BigInt.from(0x80));
      expect(s, BigInt.one);
    });

    test('decodeDer refuses anything but SEQUENCE { r, s }', () {
      expect(
        () => Secp256k1.decodeDer(derInteger(BigInt.one)),
        throwsA(
          isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('not a DER SEQUENCE'),
          ),
        ),
      );
      expect(
        () => Secp256k1.decodeDer(derSequence([derInteger(BigInt.one)])),
        throwsA(
          isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('has 1 components'),
          ),
        ),
      );
      expect(
        () => Secp256k1.decodeDer(
          derSequence([
            derInteger(BigInt.one),
            derInteger(BigInt.one),
            derInteger(BigInt.one),
          ]),
        ),
        throwsA(
          isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('has 3 components'),
          ),
        ),
      );
    });
  });

  group('low and high S', () {
    late BigInt r;
    late BigInt s;
    late Uint8List signature;

    setUp(() {
      signature = Secp256k1.sign(message, pair.privateKey);
      (r, s) = Secp256k1.decodeDer(signature);
    });

    test('sign always emits low S', () {
      expect(s <= (n >> 1), isTrue);
      expect(Secp256k1.isHighS(signature), isFalse);
    });

    test('lowS folds an upper-half S and leaves a lower-half one alone', () {
      expect(Secp256k1.lowS(n - s), s);
      expect(Secp256k1.lowS(s), s);
      final half = n >> 1;
      expect(Secp256k1.lowS(half), half);
      expect(Secp256k1.lowS(half + BigInt.one), n - half - BigInt.one);
    });

    test('isHighS spots the mirrored signature, which still verifies', () {
      final high = Secp256k1.encodeDer(r, n - s);
      expect(Secp256k1.isHighS(high), isTrue);
      expect(Secp256k1.verify(message, high, pair.publicKey), isTrue);
    });

    test('isHighS on malformed DER throws rather than answering', () {
      expect(
        () => Secp256k1.isHighS(Uint8List.fromList([1, 2])),
        throwsFormatException,
      );
    });
  });

  group('verify', () {
    late Uint8List signature;
    late BigInt r;
    late BigInt s;

    setUp(() {
      signature = Secp256k1.sign(message, pair.privateKey);
      (r, s) = Secp256k1.decodeDer(signature);
    });

    test('accepts the signature it just made, with either key encoding', () {
      expect(Secp256k1.verify(message, signature, pair.publicKey), isTrue);
      final compressed = Secp256k1.fromScalar(
        pair.privateKey,
        compressed: true,
      ).publicKey;
      expect(Secp256k1.verify(message, signature, compressed), isTrue);
    });

    test('rejects another message, another key, and a flipped bit', () {
      expect(
        Secp256k1.verify(
          Uint8List.fromList([...message, 0]),
          signature,
          pair.publicKey,
        ),
        isFalse,
      );
      final other = Secp256k1.fromScalar(scalar(BigInt.two));
      expect(Secp256k1.verify(message, signature, other.publicKey), isFalse);
      final flipped = Uint8List.fromList(signature)
        ..[signature.length - 1] ^= 1;
      expect(Secp256k1.verify(message, flipped, pair.publicKey), isFalse);
    });

    test('rejects r or s of zero or at least n', () {
      for (final bad in [BigInt.zero, n, n + BigInt.one]) {
        expect(
          Secp256k1.verify(
            message,
            Secp256k1.encodeDer(bad, s),
            pair.publicKey,
          ),
          isFalse,
          reason: 'r = $bad',
        );
        expect(
          Secp256k1.verify(
            message,
            Secp256k1.encodeDer(r, bad),
            pair.publicKey,
          ),
          isFalse,
          reason: 's = $bad',
        );
      }
    });

    test('returns false, never throws, for malformed input', () {
      expect(Secp256k1.verify(message, Uint8List(0), pair.publicKey), isFalse);
      expect(
        Secp256k1.verify(
          message,
          Uint8List.fromList([0x30, 0x00]),
          pair.publicKey,
        ),
        isFalse,
      );
      expect(
        Secp256k1.verify(message, signature, Uint8List.fromList([0x00])),
        isFalse,
        reason: 'the point at infinity',
      );
      expect(
        Secp256k1.verify(message, signature, Uint8List(10)),
        isFalse,
        reason: 'not a point',
      );
      expect(
        Secp256k1.verify(message, signature, pair.publicKey.sublist(0, 40)),
        isFalse,
      );
    });
  });
}
