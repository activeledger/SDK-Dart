import 'dart:convert';
import 'dart:typed_data';

import 'package:activeledger_falcon/activeledger_falcon.dart';
import 'package:test/test.dart';

import 'support/vectors.dart';

void main() {
  setUpAll(() => ActiveledgerFalcon.enable(throwOnFailure: true));

  const crypto = DefaultCryptoProvider();
  final keys = KeyHandler();

  test('enable registers falcon-512 and makes it preferred', () {
    expect(ActiveledgerFalcon.isEnabled, isTrue);
    expect(PostQuantum.isAvailable(KeyType.falcon512), isTrue);
    expect(KeyType.preferredPostQuantum, KeyType.falcon512);
    expect(ActiveledgerFalcon.enable(), isTrue);
  });

  group('pq-vectors.json', () {
    final vectors = vectorList(
      loadVectors('pq-vectors.json'),
      'vectors',
    ).where((v) => v['type'] == 'falcon-512');
    for (final v in vectors) {
      final name = v['messageName'];
      final message = v['message']! as String;
      final pub = v['publicKey']! as String;
      final prv = v['privateKey']! as String;

      test('$name: key lengths include the header', () {
        expect(base64.decode(pub).length, 897);
        expect(base64.decode(pub)[0], 0x09);
        expect(base64.decode(prv).length, 1281);
        expect(base64.decode(prv)[0], 0x59);
      });

      test('$name: verifies the published signature', () {
        expect(
          crypto.verify(
            message,
            v['signature']! as String,
            pub,
            type: KeyType.falcon512,
          ),
          isTrue,
        );
      });

      test(
        '$name: own signatures are randomised, variable length, and verify',
        () {
          final a = crypto.sign(message, prv, type: KeyType.falcon512);
          final b = crypto.sign(message, prv, type: KeyType.falcon512);
          expect(a, isNot(b));
          for (final s in [a, b]) {
            final bytes = base64.decode(s);
            expect(bytes[0], 0x39);
            expect(bytes.length, inInclusiveRange(600, 690));
            expect(
              crypto.verify(message, s, pub, type: KeyType.falcon512),
              isTrue,
            );
          }
        },
      );

      test('$name: rejects a tampered message', () {
        expect(
          crypto.verify(
            '$message ',
            v['signature']! as String,
            pub,
            type: KeyType.falcon512,
          ),
          isFalse,
        );
      });
    }
  });

  group('seed-vectors.json', () {
    final file = loadVectors('seed-vectors.json');
    for (final v in vectorList(
      file,
      'seedVectors',
    ).where((v) => v['type'] == 'falcon-512')) {
      test('fromSeed ${v['seedName']}', () {
        final key = keys.generateKeyFromSeed(
          'k',
          hexBytes(v['seed']! as String),
          type: KeyType.falcon512,
        );
        expect(key.key.publicKey, v['publicKey']);
        expect(key.key.privateKey, v['privateKey']);
      });
    }
    for (final v in vectorList(
      file,
      'phraseVectors',
    ).where((v) => v['type'] == 'falcon-512')) {
      test('fromPhrase ${v['phraseName']}', () {
        final key = keys.restoreBip39Key(
          'k',
          v['phrase']! as String,
          type: KeyType.falcon512,
          passphrase: v['passphrase']! as String,
        );
        expect(key.key.publicKey, v['publicKey']);
        expect(key.key.privateKey, v['privateKey']);
      });
    }
  });

  test('seeded keygen leaves the system RNG in place afterwards', () {
    final seed = Uint8List(48);
    final a = keys.generateKeyFromSeed('a', seed, type: KeyType.falcon512);
    final fresh1 = keys.generateKey('x', type: KeyType.falcon512);
    final fresh2 = keys.generateKey('y', type: KeyType.falcon512);
    expect(fresh1.publicKey, isNot(a.publicKey));
    expect(fresh1.publicKey, isNot(fresh2.publicKey));
  });

  test('wrong seed length is refused', () {
    expect(
      () =>
          keys.generateKeyFromSeed('k', Uint8List(32), type: KeyType.falcon512),
      throwsA(
        isA<ArgumentError>().having(
          (e) => e.message,
          'message',
          contains('48-byte seed, got 32'),
        ),
      ),
    );
  });

  test('a header-stripped private key is named as such', () {
    final key = keys.generateKey('k', type: KeyType.falcon512);
    final stripped = base64.encode(
      base64.decode(key.key.privateKey).sublist(1),
    );
    expect(
      () => crypto.sign('x', stripped, type: KeyType.falcon512),
      throwsA(
        isA<ArgumentError>().having(
          (e) => e.message,
          'message',
          contains('header byte stripped'),
        ),
      ),
    );
  });

  test('onboarding transaction signs and verifies', () {
    final key = keys.generateKey('identity', type: KeyType.falcon512);
    final tx = TransactionHandler().buildOnboardKeyTx(key);
    expect((tx.tx[r'$i']! as Map)['identity'], {
      'publicKey': key.publicKey,
      'type': 'falcon-512',
    });
    expect(
      crypto.verify(
        tx.signedString,
        tx.sigs['identity']!,
        key.publicKey,
        type: KeyType.falcon512,
      ),
      isTrue,
    );
  });

  test('disable falls back to ml-dsa-65', () {
    ActiveledgerFalcon.disable();
    expect(KeyType.preferredPostQuantum, KeyType.mlDsa65);
    expect(
      () => keys.generateKey('k', type: KeyType.falcon512),
      throwsA(isA<KeyTypeUnavailableException>()),
    );
    ActiveledgerFalcon.enable();
  });
}
