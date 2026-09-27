import 'dart:convert';
import 'dart:io';

import 'package:activeledger/activeledger.dart';
import 'package:test/test.dart';

/// Legacy identities: RSA keys, and secp256k1 keys exported as PEM by older
/// SDKs. The fixture was signed by node:crypto, as the JavaScript SDK signs.
void main() {
  final fixture =
      (jsonDecode(File('test/fixtures/pem-keys.json').readAsStringSync())
              as Map)
          .cast<String, Object?>();
  final message = fixture['message']! as String;
  final rsa = (fixture['rsa']! as Map).cast<String, String>();
  final ec = (fixture['secp256k1']! as Map).cast<String, String>();
  const crypto = DefaultCryptoProvider();

  group('rsa', () {
    test(
      'verifies a node:crypto signature with SPKI and PKCS#1 public keys',
      () {
        for (final pub in [rsa['spki']!, rsa['pkcs1Public']!]) {
          expect(
            crypto.verify(message, rsa['signature']!, pub, type: KeyType.rsa),
            isTrue,
          );
        }
      },
    );

    test('signs identically to node:crypto from PKCS#8 and PKCS#1', () {
      // PKCS#1 v1.5 is deterministic, so the bytes must match exactly.
      for (final prv in [rsa['pkcs8']!, rsa['pkcs1']!]) {
        expect(crypto.sign(message, prv, type: KeyType.rsa), rsa['signature']);
      }
    });

    test('rejects a tampered message', () {
      expect(
        crypto.verify(
          '$message.',
          rsa['signature']!,
          rsa['spki']!,
          type: KeyType.rsa,
        ),
        isFalse,
      );
    });

    test('an rsa key must be PEM', () {
      expect(
        () => crypto.sign(message, '0x01', type: KeyType.rsa),
        throwsArgumentError,
      );
    });
  });

  group('secp256k1 as PEM', () {
    test('verifies a node:crypto signature with an SPKI public key', () {
      expect(crypto.verify(message, ec['signature']!, ec['spki']!), isTrue);
    });

    test('the hex form of the same key verifies it too', () {
      expect(
        crypto.verify(message, ec['signature']!, ec['hexPublic']!),
        isTrue,
      );
    });

    test('signs from SEC1 and PKCS#8 exactly as from hex', () {
      final expected = crypto.sign(message, ec['hexPrivate']!);
      expect(crypto.sign(message, ec['sec1']!), expected);
      expect(crypto.sign(message, ec['pkcs8']!), expected);
      expect(crypto.verify(message, expected, ec['spki']!), isTrue);
    });
  });
}
