import 'dart:convert';

import 'package:activeledger_falcon/activeledger_falcon.dart';
import 'package:test/test.dart';

void main() {
  // Each case restores the add-on, because the boundary is process-global.
  setUp(() => ActiveledgerFalcon.enable(throwOnFailure: true));
  tearDownAll(ActiveledgerFalcon.disable);

  final keys = KeyHandler();
  final transactions = TransactionHandler();
  final payloads = PayloadHandler();
  const crypto = DefaultCryptoProvider();

  group('enable and disable', () {
    test('disable clears every observable flag', () {
      ActiveledgerFalcon.disable();
      expect(ActiveledgerFalcon.isEnabled, isFalse);
      expect(PostQuantum.isAvailable(KeyType.falcon512), isFalse);
      expect(KeyType.preferredPostQuantum, KeyType.mlDsa65);
    });

    test('disable twice is harmless and keeps ml-dsa-65 working', () {
      ActiveledgerFalcon.disable();
      ActiveledgerFalcon.disable();
      expect(PostQuantum.isAvailable(KeyType.mlDsa65), isTrue);
      final key = keys.generateKey('k', type: KeyType.mlDsa65);
      final signature = payloads.sign({'a': 1}, key);
      expect(
        payloads.verify({'a': 1}, signature, key.publicKey, type: key.type),
        isTrue,
      );
    });

    test('enable after disable restores falcon-512 as preferred', () {
      ActiveledgerFalcon.disable();
      expect(ActiveledgerFalcon.enable(), isTrue);
      expect(ActiveledgerFalcon.isEnabled, isTrue);
      expect(ActiveledgerFalcon.failure, isNull);
      expect(KeyType.preferredPostQuantum, KeyType.falcon512);
      expect(
        keys.generateKey('k', type: KeyType.falcon512).type,
        KeyType.falcon512,
      );
    });

    test('keys made by preferredPostQuantum follow the boundary', () {
      expect(
        keys.generateKey('a', type: KeyType.preferredPostQuantum).type,
        KeyType.falcon512,
      );
      ActiveledgerFalcon.disable();
      expect(
        keys.generateKey('b', type: KeyType.preferredPostQuantum).type,
        KeyType.mlDsa65,
      );
    });
  });

  group('a falcon key outliving the add-on', () {
    test('cannot sign once disabled, and the error says how to fix it', () {
      final key = keys.generateKey('k', type: KeyType.falcon512)
        ..identity = 'stream';
      ActiveledgerFalcon.disable();
      expect(
        () => payloads.sign({'a': 1}, key),
        throwsA(
          isA<KeyTypeUnavailableException>().having(
            (e) => e.message,
            'message',
            contains('ActiveledgerFalcon.enable()'),
          ),
        ),
      );
      expect(
        () => transactions.labelledTransaction(
          key: key,
          namespace: 'n',
          contract: 'c',
          inputLabel: 'i',
          stream: 'stream',
        ),
        throwsA(isA<KeyTypeUnavailableException>()),
      );
    });

    test('verifies as false, not true or a throw, once disabled', () {
      final key = keys.generateKey('k', type: KeyType.falcon512);
      final signature = payloads.sign('hello', key);
      expect(
        payloads.verify('hello', signature, key.publicKey, type: key.type),
        isTrue,
      );
      ActiveledgerFalcon.disable();
      expect(
        payloads.verify('hello', signature, key.publicKey, type: key.type),
        isFalse,
      );
      expect(
        crypto.verify('hello', signature, key.publicKey, type: key.type),
        isFalse,
      );
    });

    test('the same signature verifies again after re-enabling', () {
      final key = keys.generateKey('k', type: KeyType.falcon512);
      final signature = payloads.sign('hello', key);
      ActiveledgerFalcon.disable();
      ActiveledgerFalcon.enable();
      expect(
        payloads.verify('hello', signature, key.publicKey, type: key.type),
        isTrue,
      );
    });

    test('a key phrase still restores a falcon key after re-enabling', () {
      final original = keys.generateBip39Key('k', type: KeyType.falcon512);
      ActiveledgerFalcon.disable();
      expect(
        () => keys.restoreBip39Key(
          'k',
          original.phrase!,
          type: KeyType.falcon512,
        ),
        throwsA(isA<KeyTypeUnavailableException>()),
      );
      ActiveledgerFalcon.enable();
      final restored = keys.restoreBip39Key(
        'k',
        original.phrase!,
        type: KeyType.falcon512,
      );
      expect(restored.publicKey, original.publicKey);
      expect(restored.key.privateKey, original.key.privateKey);
    });
  });

  group('falcon-512 through the SDK surface', () {
    test('labelledTransaction signs and verifies', () {
      final key = keys.generateKey('k', type: KeyType.falcon512)
        ..identity = 'stream';
      final tx = transactions.labelledTransaction(
        key: key,
        namespace: 'n',
        contract: 'c',
        inputLabel: 'i',
        stream: 'stream',
        inputData: {'amount': 1},
      );
      expect(
        crypto.verify(
          tx.signedString,
          tx.sigs['stream']!,
          key.publicKey,
          type: KeyType.falcon512,
        ),
        isTrue,
      );
      tx.tx[r'$namespace'] = 'other';
      expect(
        crypto.verify(
          tx.signedString,
          tx.sigs['stream']!,
          key.publicKey,
          type: KeyType.falcon512,
        ),
        isFalse,
      );
    });

    test('self-signed input advertises falcon-512', () {
      final key = keys.generateKey('k', type: KeyType.falcon512)
        ..identity = 'stream';
      final tx = transactions.labelledTransaction(
        key: key,
        namespace: 'n',
        contract: 'c',
        inputLabel: 'i',
        stream: 'stream',
        selfsign: true,
      );
      final input = (tx.tx[r'$i']! as Map)['i'] as Map;
      expect(input['type'], 'falcon-512');
      expect(input['publicKey'], key.publicKey);
      expect(tx.sigs.keys, ['i']);
    });

    test('payload signatures are bound to the key and to the payload', () {
      final a = keys.generateKey('a', type: KeyType.falcon512);
      final b = keys.generateKey('b', type: KeyType.falcon512);
      final signature = payloads.sign({'x': 1}, a);
      bool check(Object? payload, String publicKey) =>
          payloads.verify(payload, signature, publicKey, type: a.type);
      expect(check({'x': 1}, a.publicKey), isTrue);
      expect(check({'x': 2}, a.publicKey), isFalse);
      expect(check({'x': 1}, b.publicKey), isFalse);
    });

    test('a corrupted or truncated signature verifies false', () {
      final key = keys.generateKey('k', type: KeyType.falcon512);
      final bytes = base64.decode(payloads.sign('m', key));
      final flipped = List<int>.of(bytes)..[bytes.length ~/ 2] ^= 1;
      expect(
        payloads.verify(
          'm',
          base64.encode(flipped),
          key.publicKey,
          type: key.type,
        ),
        isFalse,
      );
      expect(
        payloads.verify(
          'm',
          base64.encode(bytes.sublist(0, 10)),
          key.publicKey,
          type: key.type,
        ),
        isFalse,
      );
      expect(payloads.verify('m', '', key.publicKey, type: key.type), isFalse);
    });

    test('a key file round-trips and still signs', () {
      final key = keys.generateKey('k', type: KeyType.falcon512)
        ..identity = 'id';
      final back = Key.fromJson(
        jsonDecode(jsonEncode(key.toJson())) as Map<String, Object?>,
      );
      expect(back.type, KeyType.falcon512);
      final signature = payloads.sign('m', back);
      expect(
        payloads.verify('m', signature, key.publicKey, type: key.type),
        isTrue,
      );
    });

    test('a public key of the wrong length is rejected by KeyCodec', () {
      final key = keys.generateKey('k', type: KeyType.falcon512);
      KeyCodec.checkPublicKey(KeyType.falcon512, key.publicKey);
      final stripped = base64.encode(base64.decode(key.publicKey).sublist(1));
      expect(
        () => KeyCodec.checkPublicKey(KeyType.falcon512, stripped),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('header byte stripped'),
          ),
        ),
      );
    });
  });
}
