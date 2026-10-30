import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:activeledger/activeledger.dart';
import 'package:test/test.dart';

void main() {
  final keys = KeyHandler();

  Map<String, Object?> valid() => {
    'name': 'me',
    'type': 'secp256k1',
    'key': {
      'prv': {'pkcs8pem': '0x${'11' * 32}'},
      'pub': {'pkcs8pem': '0x02${'22' * 32}'},
    },
  };

  group('Key.fromJson', () {
    test('reads every field', () {
      final key = Key.fromJson({
        ...valid(),
        'identity': 'stream',
        'phrase': 'some words',
      });
      expect(key.name, 'me');
      expect(key.type, KeyType.secp256k1);
      expect(key.identity, 'stream');
      expect(key.phrase, 'some words');
      expect(key.publicKey, '0x02${'22' * 32}');
      expect(key.key.privateKey, '0x${'11' * 32}');
    });

    test('a missing name is refused', () {
      expect(
        () => Key.fromJson(valid()..remove('name')),
        throwsFormatException,
      );
    });

    test('a missing type is refused rather than defaulted to rsa', () {
      expect(
        () => Key.fromJson(valid()..remove('type')),
        throwsA(
          isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('type'),
          ),
        ),
      );
    });

    test('an unknown type is refused', () {
      expect(
        () => Key.fromJson(valid()..['type'] = 'dsa'),
        throwsArgumentError,
      );
    });

    test('a missing key is refused', () {
      expect(() => Key.fromJson(valid()..remove('key')), throwsFormatException);
    });

    for (final half in ['pub', 'prv']) {
      test('a key file without $half.pkcs8pem names the missing half', () {
        final json = valid();
        (json['key']! as Map).remove(half);
        expect(
          () => Key.fromJson(json),
          throwsA(
            isA<FormatException>().having(
              (e) => e.message,
              'message',
              contains(half),
            ),
          ),
        );
      });
    }

    test('a non-string pkcs8pem is refused', () {
      final json = valid();
      json['key'] = {
        'prv': {'pkcs8pem': '0x${'11' * 32}'},
        'pub': {'pkcs8pem': 5},
      };
      expect(() => Key.fromJson(json), throwsFormatException);
    });
  });

  group('Key.toJson', () {
    test('omits identity and phrase until they exist', () {
      final key = keys.generateKey('plain');
      expect(key.toJson().keys.toSet(), {'key', 'name', 'type'});
    });

    test(
      'includes identity once onboarded, and a phrase when there is one',
      () {
        final key = keys.generateBip39Key('seeded')..identity = 'stream';
        final json = key.toJson();
        expect(json['identity'], 'stream');
        expect(json['phrase'], key.phrase);
        expect(json['type'], 'secp256k1');
      },
    );

    test('round-trips through JSON for every locally available type', () {
      for (final type in [KeyType.secp256k1, KeyType.mlDsa65]) {
        final key = keys.generateKey('k', type: type)..identity = 'id';
        final back = Key.fromJson(
          jsonDecode(jsonEncode(key.toJson())) as Map<String, Object?>,
        );
        expect(back.toJson(), key.toJson());
        expect(back.type, type);
      }
    });

    test('KeyMaterial uses the pkcs8pem field name for every key type', () {
      final material = keys.generateKey('k', type: KeyType.mlDsa65).key;
      final json = material.toJson();
      expect((json['pub']! as Map).keys, ['pkcs8pem']);
      expect((json['prv']! as Map)['pkcs8pem'], material.privateKey);
    });
  });

  test('Key.toString shows the identity only once there is one', () {
    final key = keys.generateKey('me');
    expect(key.toString(), 'Key(me, secp256k1)');
    key.identity = 'abc';
    expect(key.toString(), 'Key(me, secp256k1, abc)');
  });

  group('generateKey', () {
    test(
      'compressed and uncompressed secp256k1 public keys differ in size',
      () {
        final uncompressed = keys.generateKey('a').publicKey;
        final compressed = keys.generateKey('a', compressed: true).publicKey;
        expect(uncompressed, startsWith('0x04'));
        expect(uncompressed.length, 2 + 65 * 2);
        expect(compressed.length, 2 + 33 * 2);
        expect(compressed, matches(RegExp('^0x0[23]')));
      },
    );

    test('two generated keys are different', () {
      expect(
        keys.generateKey('a').key.privateKey,
        isNot(keys.generateKey('a').key.privateKey),
      );
    });

    test('generateKeyFromSeed is deterministic and honours compressed', () {
      Uint8List seed() => Uint8List.fromList(List.filled(32, 7));
      final a = keys.generateKeyFromSeed('a', seed());
      final b = keys.generateKeyFromSeed('b', seed());
      expect(a.key.privateKey, b.key.privateKey);
      expect(a.publicKey, b.publicKey);
      final c = keys.generateKeyFromSeed('c', seed(), compressed: true);
      expect(c.key.privateKey, a.key.privateKey);
      expect(c.publicKey, isNot(a.publicKey));
      expect(c.publicKey.length, 2 + 33 * 2);
    });
  });

  group('importKey and exportKey errors', () {
    late Directory dir;
    setUp(() async => dir = await Directory.systemTemp.createTemp('al-keys'));
    tearDown(() => dir.delete(recursive: true));

    test('a missing file is a FileSystemException', () async {
      await expectLater(
        keys.importKey('${dir.path}/nope.json'),
        throwsA(isA<FileSystemException>()),
      );
    });

    test('a file that is not an object is a FormatException', () async {
      final file = File('${dir.path}/list.json')..writeAsStringSync('[1]');
      await expectLater(
        keys.importKey(file.path),
        throwsA(isA<FormatException>()),
      );
    });

    test('a file that is not JSON is a FormatException', () async {
      final file = File('${dir.path}/junk.json')..writeAsStringSync('nope');
      await expectLater(
        keys.importKey(file.path),
        throwsA(isA<FormatException>()),
      );
    });

    test('exportKey honours a custom file name', () async {
      await keys.exportKey(keys.generateKey('orig'), dir.path, name: 'other');
      expect(File('${dir.path}/other.json').existsSync(), isTrue);
      expect(File('${dir.path}/orig.json').existsSync(), isFalse);
    });
  });
}
