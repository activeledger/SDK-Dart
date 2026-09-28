import 'dart:convert';
import 'dart:io';

import 'package:activeledger/activeledger.dart';
import 'package:test/test.dart';

void main() {
  final keys = KeyHandler();
  final payloads = PayloadHandler();

  group('PayloadHandler', () {
    for (final type in [KeyType.secp256k1, KeyType.mlDsa65]) {
      test('${type.wire}: sign and verify an object', () {
        final key = keys.generateKey('k', type: type);
        final order = {'pair': 'VNR/USDT', 'side': 'sell', 'amount': 1.5};
        final signature = payloads.sign(order, key);
        expect(
          payloads.verify(order, signature, key.publicKey, type: type),
          isTrue,
        );
        expect(
          payloads.verify(
            payloads.canonical(order),
            signature,
            key.publicKey,
            type: type,
          ),
          isTrue,
        );
      });
    }

    test('key order matters', () {
      final key = keys.generateKey('k');
      final signature = payloads.sign({
        'pair': 'VNR/USDT',
        'side': 'sell',
      }, key);
      expect(
        payloads.verify(
          {'side': 'sell', 'pair': 'VNR/USDT'},
          signature,
          key.publicKey,
        ),
        isFalse,
      );
    });

    test('malformed input verifies false', () {
      expect(payloads.verify('x', '???', 'garbage'), isFalse);
      expect(payloads.verify(Object(), 'AAAA', 'garbage'), isFalse);
    });
  });

  group('key files', () {
    late Directory dir;
    setUp(() async => dir = await Directory.systemTemp.createTemp('al-keys'));
    tearDown(() => dir.delete(recursive: true));

    test('export and import round-trip', () async {
      final key = keys.generateBip39Key('alice', type: KeyType.mlDsa65)
        ..identity = 'stream';
      await keys.exportKey(key, dir.path);
      final back = await keys.importKey('${dir.path}/alice.json');
      expect(back.toJson(), key.toJson());
    });

    test('refuses to overwrite unless asked', () async {
      final key = keys.generateKey('bob');
      await keys.exportKey(key, dir.path);
      await expectLater(
        keys.exportKey(key, dir.path),
        throwsA(isA<FileSystemException>()),
      );
      await keys.exportKey(key, '${dir.path}/', overwrite: true, name: 'bob');
    });

    test('creates the directory when asked', () async {
      final key = keys.generateKey('carol');
      final nested = '${dir.path}/a/b';
      await expectLater(
        keys.exportKey(key, nested),
        throwsA(isA<FileSystemException>()),
      );
      await keys.exportKey(key, nested, createDir: true);
      expect(File('$nested/carol.json').existsSync(), isTrue);
    });

    test('imports the JavaScript SDK key file shape', () async {
      final file = File('${dir.path}/js.json');
      await file.writeAsString(
        jsonEncode({
          'key': {
            'prv': {'pkcs8pem': '0x${'11' * 32}'},
            'pub': {'pkcs8pem': '0x02${'22' * 32}'},
          },
          'name': 'js',
          'type': 'secp256k1',
          'identity': 'abc',
        }),
      );
      final key = await keys.importKey(file.path);
      expect(key.name, 'js');
      expect(key.type, KeyType.secp256k1);
      expect(key.identity, 'abc');
      expect(key.key.privateKey, '0x${'11' * 32}');
    });
  });
}
