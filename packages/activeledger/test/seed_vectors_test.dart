import 'dart:typed_data';

import 'package:activeledger/activeledger.dart';
import 'package:test/test.dart';

import 'support/vectors.dart';

void main() {
  final file = loadVectors('seed-vectors.json');
  final keys = KeyHandler();

  test('seed sizes match the published table', () {
    final sizes = (file['seedSizes']! as Map).cast<String, int>();
    for (final entry in sizes.entries) {
      expect(Recovery.seedSize(KeyType.fromWire(entry.key)), entry.value);
    }
  });

  group('seedVectors (fromSeed)', () {
    for (final v in vectorList(file, 'seedVectors')) {
      final type = KeyType.fromWire(v['type']! as String);
      // Falcon lives in the add-on package, and is tested there.
      if (type == KeyType.falcon512) continue;

      final form = v['publicKeyForm'];
      final name =
          '${type.wire} ${v['seedName']}${form == null ? '' : ' $form'}';
      final seed = hexBytes(v['seed']! as String);
      final compressed = form == 'compressed';

      if (v['valid'] == false) {
        test('$name: refused (${v['reason']})', () {
          expect(
            () => keys.generateKeyFromSeed(
              'k',
              seed,
              type: type,
              compressed: compressed,
            ),
            throwsArgumentError,
          );
        });
        continue;
      }

      test(name, () {
        final key = keys.generateKeyFromSeed(
          'k',
          seed,
          type: type,
          compressed: compressed,
        );
        expect(key.key.publicKey, v['publicKey']);
        expect(key.key.privateKey, v['privateKey']);
      });
    }
  });

  group('phraseVectors (fromPhrase)', () {
    for (final v in vectorList(file, 'phraseVectors')) {
      final type = KeyType.fromWire(v['type']! as String);
      final form = v['publicKeyForm'];
      final legacy = v['scheme'] == 'legacy';
      final name =
          '${type.wire} ${v['phraseName']} ${v['scheme']}'
          '${form == null ? '' : ' $form'}';
      final phrase = v['phrase']! as String;
      final passphrase = v['passphrase']! as String;

      if (!legacy) {
        test('$name: intermediate seeds', () {
          final bip39 = Recovery.toSeed(phrase, passphrase: passphrase);
          expect(toHex(bip39), v['bip39Seed']);
          expect(toHex(Recovery.deriveSeed(type, bip39)), v['derivedSeed']);
        });
      } else {
        test('$name: legacy seed', () {
          expect(toHex(Recovery.legacySeed(phrase)), v['derivedSeed']);
        });
      }

      if (type == KeyType.falcon512) continue;

      test('$name: key', () {
        final key = keys.restoreBip39Key(
          'k',
          phrase,
          type: type,
          passphrase: passphrase,
          legacy: legacy,
          compressed: form == 'compressed',
        );
        expect(key.key.publicKey, v['publicKey']);
        expect(key.key.privateKey, v['privateKey']);
        expect(key.phrase, phrase);
      });
    }
  });

  group('validation', () {
    const good =
        'abandon abandon abandon abandon abandon abandon abandon '
        'abandon abandon abandon abandon about';

    test('normalises whitespace', () {
      expect(Recovery.validate('  $good\n'.replaceAll(' ', '  ')), good);
    });

    test('names a word that is not in the list', () {
      expect(
        () => Recovery.validate(good.replaceFirst('about', 'abut')),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('word 12 ("abut")'),
          ),
        ),
      );
    });

    test('rejects a bad checksum', () {
      expect(
        () => Recovery.validate(good.replaceFirst('about', 'abandon')),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('checksum'),
          ),
        ),
      );
    });

    test('rejects a bad word count', () {
      expect(() => Recovery.validate('abandon about'), throwsArgumentError);
    });

    test('restoreBip39Key validates unless told not to', () {
      expect(
        () => keys.restoreBip39Key('k', 'not a mnemonic'),
        throwsArgumentError,
      );
      expect(
        keys.restoreBip39Key('k', 'not a mnemonic', validate: false).type,
        KeyType.secp256k1,
      );
    });

    test('legacy is secp256k1 only', () {
      expect(
        () => keys.restoreBip39Key(
          'k',
          good,
          type: KeyType.mlDsa65,
          legacy: true,
        ),
        throwsArgumentError,
      );
    });

    test('wrong seed lengths are refused, never padded', () {
      expect(
        () => keys.generateKeyFromSeed('k', Uint8List(31)),
        throwsArgumentError,
      );
      expect(
        () =>
            keys.generateKeyFromSeed('k', Uint8List(48), type: KeyType.mlDsa65),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('32-byte seed, got 48'),
          ),
        ),
      );
      expect(
        () => Recovery.deriveSeed(KeyType.mlDsa65, Uint8List(32)),
        throwsArgumentError,
      );
    });
  });

  group('generateMnemonic', () {
    test('produces valid phrases of every length', () {
      for (final (strength, words) in [
        (128, 12),
        (160, 15),
        (192, 18),
        (224, 21),
        (256, 24),
      ]) {
        final phrase = Recovery.generateMnemonic(strength: strength);
        expect(phrase.split(' '), hasLength(words));
        expect(Recovery.validate(phrase), phrase);
      }
    });

    test('generateBip39Key returns a phrase that restores the same key', () {
      final key = keys.generateBip39Key('k', type: KeyType.mlDsa65);
      final again = keys.restoreBip39Key(
        'k',
        key.phrase!,
        type: KeyType.mlDsa65,
      );
      expect(again.key.publicKey, key.key.publicKey);
    });
  });
}
