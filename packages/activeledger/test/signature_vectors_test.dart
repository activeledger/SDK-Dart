import 'dart:convert';
import 'dart:typed_data';

import 'package:activeledger/activeledger.dart';
import 'package:test/test.dart';

import 'support/vectors.dart';

void main() {
  final vectors = vectorList(loadVectors('pq-vectors.json'), 'vectors');
  const crypto = DefaultCryptoProvider();

  group('secp256k1 (pq-vectors.json)', () {
    for (final v in vectors.where((v) => v['type'] == 'secp256k1')) {
      final name = '${v['messageName']} ${v['publicKeyForm']}';
      final message = v['message']! as String;
      final pub = v['publicKey']! as String;
      final prv = v['privateKey']! as String;

      test('$name: verifies the OpenSSL signature', () {
        expect(crypto.verify(message, v['signature']! as String, pub), isTrue);
      });

      test('$name: verifies the high-S signature', () {
        final highS = v['highSSignature']! as String;
        expect(Secp256k1.isHighS(base64.decode(highS)), isTrue);
        expect(crypto.verify(message, highS, pub), isTrue);
      });

      test('$name: signs byte-for-byte as RFC 6979 low-S', () {
        final signature = crypto.sign(message, prv);
        expect(signature, v['deterministicSignature']);
        expect(Secp256k1.isHighS(base64.decode(signature)), isFalse);
      });

      test('$name: derives the public key from the private key', () {
        final compressed = v['publicKeyForm'] == 'compressed';
        final keys = crypto.generateFromSeed(
          Secp256k1.fromHex(prv, 'private'),
          compressed: compressed,
        );
        expect(keys.publicKey, pub);
        expect(keys.privateKey, prv);
      });

      test('$name: rejects a tampered message', () {
        expect(
          crypto.verify('$message ', v['signature']! as String, pub),
          isFalse,
        );
      });
    }
  });

  group('ml-dsa-65 (pq-vectors.json)', () {
    for (final v in vectors.where((v) => v['type'] == 'ml-dsa-65')) {
      final name = v['messageName'];
      final message = v['message']! as String;
      final pub = v['publicKey']! as String;
      final prv = v['privateKey']! as String;

      test('$name: key lengths', () {
        expect(base64.decode(pub).length, v['publicKeyBytes']);
        expect(base64.decode(prv).length, v['privateKeyBytes']);
      });

      test('$name: verifies the published signature', () {
        expect(
          crypto.verify(
            message,
            v['signature']! as String,
            pub,
            type: KeyType.mlDsa65,
          ),
          isTrue,
        );
      });

      test('$name: own signatures are hedged and verify', () {
        final a = crypto.sign(message, prv, type: KeyType.mlDsa65);
        final b = crypto.sign(message, prv, type: KeyType.mlDsa65);
        expect(a, isNot(b));
        expect(base64.decode(a).length, 3309);
        expect(crypto.verify(message, a, pub, type: KeyType.mlDsa65), isTrue);
        expect(crypto.verify(message, b, pub, type: KeyType.mlDsa65), isTrue);
      });

      test('$name: rejects a tampered message', () {
        expect(
          crypto.verify(
            '$message ',
            v['signature']! as String,
            pub,
            type: KeyType.mlDsa65,
          ),
          isFalse,
        );
      });
    }
  });

  group('malformed input', () {
    final v = vectors.firstWhere((v) => v['type'] == 'ml-dsa-65');

    test('verify returns false rather than throwing', () {
      final pub = v['publicKey']! as String;
      expect(
        crypto.verify('x', 'not base64!', pub, type: KeyType.mlDsa65),
        isFalse,
      );
      expect(crypto.verify('x', 'AAAA', pub, type: KeyType.mlDsa65), isFalse);
      expect(
        crypto.verify('x', 'AAAA', 'AAAA', type: KeyType.mlDsa65),
        isFalse,
      );
      expect(crypto.verify('x', 'AAAA', '0x02'), isFalse);
      expect(crypto.verify('x', 'AAAA', 'no prefix'), isFalse);
    });

    test('signing with a wrong-length key names the problem', () {
      expect(
        () => crypto.sign(
          'x',
          base64.encode(Uint8List(100)),
          type: KeyType.mlDsa65,
        ),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('4032 bytes, got 100'),
          ),
        ),
      );
    });

    test('secp256k1 keys must carry the 0x prefix', () {
      expect(() => crypto.sign('x', 'b69fbf24'), throwsArgumentError);
    });

    test('a hex key for a post-quantum type is named as such', () {
      expect(
        () => crypto.sign('x', '0xabcd', type: KeyType.mlDsa65),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('hex'),
          ),
        ),
      );
    });
  });

  group('KeyType', () {
    test('wire strings', () {
      expect(KeyType.values.map((t) => t.wire), [
        'secp256k1',
        'ml-dsa-65',
        'falcon-512',
        'rsa',
      ]);
    });

    test('fromWire is strict and accepts the ledger aliases', () {
      expect(KeyType.fromWire('ml-dsa-65'), KeyType.mlDsa65);
      expect(KeyType.fromWire('bitcoin'), KeyType.secp256k1);
      expect(KeyType.fromWire('ethereum'), KeyType.secp256k1);
      expect(() => KeyType.fromWire('ML-DSA-65'), throwsArgumentError);
    });
  });

  group('without the Falcon add-on', () {
    test('falcon-512 is unavailable and says how to fix it', () {
      expect(PostQuantum.isAvailable(KeyType.falcon512), isFalse);
      expect(
        () => crypto.generate(type: KeyType.falcon512),
        throwsA(
          isA<KeyTypeUnavailableException>().having(
            (e) => e.message,
            'message',
            contains('activeledger_falcon'),
          ),
        ),
      );
    });

    test('preferredPostQuantum falls back to ml-dsa-65', () {
      expect(KeyType.preferredPostQuantum, KeyType.mlDsa65);
    });

    test('falcon-512 seeds still derive from a phrase', () {
      final seed = Recovery.deriveSeed(
        KeyType.falcon512,
        Recovery.toSeed(
          'abandon abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon about',
        ),
      );
      expect(seed.length, 48);
    });
  });

  test('rsa keys cannot be generated', () {
    expect(() => crypto.generate(type: KeyType.rsa), throwsArgumentError);
  });
}
