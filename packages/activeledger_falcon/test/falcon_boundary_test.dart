import 'dart:convert';
import 'dart:typed_data';

import 'package:activeledger_falcon/activeledger_falcon.dart';
import 'package:test/test.dart';

/// The add-on boundary with Falcon-512 NOT enabled.
///
/// Nothing in this file may call `ActiveledgerFalcon.enable()` or touch
/// liboqs. Enabling loads a process-wide native library whose RNG hooks
/// (used by every Falcon key generation) are bound to one isolate, and
/// `dart test` runs files on separate isolates concurrently - so a second
/// file driving liboqs races `falcon_test.dart` and aborts the VM with
/// "Cannot invoke native callback from a different isolate". The enabled
/// behaviour is covered by `falcon_test.dart`; this file covers what the
/// SDK promises when the add-on is absent or has been disabled.
void main() {
  final keys = KeyHandler();
  final transactions = TransactionHandler();
  final payloads = PayloadHandler();
  const crypto = DefaultCryptoProvider();

  // Never registered, so every case here sees the add-on as absent.
  setUpAll(ActiveledgerFalcon.disable);

  // A falcon-512 key with the right lengths and headers, built by hand so
  // no native code is needed. It is only ever used where the SDK must refuse
  // before reaching a signature scheme.
  Uint8List bytes(int length, int header) => Uint8List(length)..[0] = header;
  final falconKey = Key(
    name: 'k',
    type: KeyType.falcon512,
    key: KeyMaterial(
      publicKey: base64.encode(bytes(897, 0x09)),
      privateKey: base64.encode(bytes(1281, 0x59)),
    ),
    identity: 'stream',
  );

  group('with the add-on absent', () {
    test('every observable flag says falcon-512 is off', () {
      expect(ActiveledgerFalcon.isEnabled, isFalse);
      expect(ActiveledgerFalcon.failure, isNull);
      expect(PostQuantum.isAvailable(KeyType.falcon512), isFalse);
      expect(KeyType.preferredPostQuantum, KeyType.mlDsa65);
    });

    test('disable twice is harmless and keeps ml-dsa-65 working', () {
      ActiveledgerFalcon.disable();
      ActiveledgerFalcon.disable();
      expect(ActiveledgerFalcon.isEnabled, isFalse);
      expect(PostQuantum.isAvailable(KeyType.mlDsa65), isTrue);
      final key = keys.generateKey('k', type: KeyType.mlDsa65);
      final signature = payloads.sign({'a': 1}, key);
      expect(
        payloads.verify({'a': 1}, signature, key.publicKey, type: key.type),
        isTrue,
      );
    });

    test('preferredPostQuantum keys fall back to ml-dsa-65', () {
      expect(
        keys.generateKey('b', type: KeyType.preferredPostQuantum).type,
        KeyType.mlDsa65,
      );
    });

    test('generating a falcon key says how to fix it', () {
      expect(
        () => keys.generateKey('k', type: KeyType.falcon512),
        throwsA(
          isA<KeyTypeUnavailableException>().having(
            (e) => e.message,
            'message',
            contains('ActiveledgerFalcon.enable()'),
          ),
        ),
      );
    });

    test('a key phrase cannot restore a falcon key', () {
      expect(
        () => keys.restoreBip39Key(
          'k',
          'abandon abandon abandon abandon abandon abandon '
              'abandon abandon abandon abandon abandon about',
          type: KeyType.falcon512,
        ),
        throwsA(isA<KeyTypeUnavailableException>()),
      );
    });
  });

  group('a falcon key without the add-on', () {
    test('cannot sign, and the error says how to fix it', () {
      expect(
        () => payloads.sign({'a': 1}, falconKey),
        throwsA(
          isA<KeyTypeUnavailableException>().having(
            (e) => e.message,
            'message',
            contains('ActiveledgerFalcon.enable()'),
          ),
        ),
      );
      expect(
        () =>
            crypto.sign('m', falconKey.key.privateKey, type: KeyType.falcon512),
        throwsA(isA<KeyTypeUnavailableException>()),
      );
    });

    test('cannot build a signed transaction', () {
      expect(
        () => transactions.labelledTransaction(
          key: falconKey,
          namespace: 'n',
          contract: 'c',
          inputLabel: 'i',
          stream: 'stream',
        ),
        throwsA(isA<KeyTypeUnavailableException>()),
      );
    });

    test('verifies as false, never true and never a throw', () {
      final signature = base64.encode(bytes(650, 0x39));
      expect(
        payloads.verify(
          'hello',
          signature,
          falconKey.publicKey,
          type: falconKey.type,
        ),
        isFalse,
      );
      expect(
        crypto.verify(
          'hello',
          signature,
          falconKey.publicKey,
          type: KeyType.falcon512,
        ),
        isFalse,
      );
    });

    test('a public key cannot be checked without a scheme', () {
      expect(
        () => KeyCodec.checkPublicKey(KeyType.falcon512, falconKey.publicKey),
        throwsA(isA<KeyTypeUnavailableException>()),
      );
    });

    test('a key file still round-trips as data', () {
      final back = Key.fromJson(
        jsonDecode(jsonEncode(falconKey.toJson())) as Map<String, Object?>,
      );
      expect(back.type, KeyType.falcon512);
      expect(back.publicKey, falconKey.publicKey);
      expect(back.key.privateKey, falconKey.key.privateKey);
      expect(back.identity, 'stream');
    });
  });
}
