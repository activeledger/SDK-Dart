import 'dart:convert';

import 'package:activeledger/activeledger.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

void main() {
  final keys = KeyHandler();

  group('exception text', () {
    test('every exception names its type and carries its detail', () {
      expect(
        ActiveledgerException('plain').toString(),
        'ActiveledgerException: plain',
      );
      expect(
        KeyTypeUnavailableException('no falcon').toString(),
        'KeyTypeUnavailableException: no falcon',
      );
      expect(
        LedgerHttpException(502, 'bad gateway').toString(),
        'LedgerHttpException: HTTP 502: bad gateway',
      );
    });

    test('KeyType prints as its wire name', () {
      expect(KeyType.secp256k1.toString(), 'secp256k1');
      expect(KeyType.mlDsa65.toString(), KeyType.mlDsa65.wire);
    });
  });

  group('onboarding replies', () {
    Connection reply(Map<String, Object?> body) => Connection.fromUrl(
      'http://node:5260',
      client: MockClient((_) async => http.Response(jsonEncode(body), 200)),
    );

    test('a committed reply that created nothing is refused', () async {
      final connection = reply({
        r'$umid': 'u',
        r'$summary': {'total': 4, 'vote': 4, 'commit': 4},
        r'$streams': {'new': [], 'updated': []},
      });
      final key = keys.generateKey('identity');
      await expectLater(
        keys.onboardKey(key, connection),
        throwsA(
          isA<OnboardException>().having(
            (e) => e.message,
            'message',
            contains('created no identity'),
          ),
        ),
      );
      expect(key.identity, isNull);
    });
  });

  group('canonical JSON entry points', () {
    test(
      'canonicalJsonBytes is the UTF-8 of canonicalJson, in insertion order',
      () {
        final value = {'b': 'é€😀', 'a': 1};
        expect(canonicalJson(value), '{"b":"é€😀","a":1}');
        expect(canonicalJsonBytes(value), utf8.encode('{"b":"é€😀","a":1}'));
      },
    );

    test('nesting beyond the limit is refused rather than overflowing', () {
      Object? deep = 1;
      for (var i = 0; i < 600; i++) {
        deep = [deep];
      }
      expect(() => canonicalJson(deep), throwsArgumentError);
    });
  });

  group('seed and mnemonic arguments', () {
    test('seed size is refused for key types that cannot be derived', () {
      expect(() => Recovery.seedSize(KeyType.rsa), throwsArgumentError);
      expect(Recovery.seedSize(KeyType.secp256k1), 32);
    });

    test('mnemonic strength must be a BIP-39 entropy size', () {
      for (final bad in [0, 96, 127, 129, 255, 288]) {
        expect(
          () => Recovery.generateMnemonic(strength: bad),
          throwsArgumentError,
          reason: 'strength $bad',
        );
      }
      expect(
        Recovery.generateMnemonic(strength: 256).split(' '),
        hasLength(24),
      );
    });
  });

  group('key pair checks', () {
    test('an ml-dsa-65 private key of the wrong length is refused', () {
      final a = keys.generateKey('a', type: KeyType.mlDsa65);
      final short = base64.encode(base64.decode(a.key.privateKey).sublist(1));
      expect(
        () => KeyCodec.checkKeyPair(KeyType.mlDsa65, a.key.publicKey, short),
        throwsArgumentError,
      );
      expect(
        () => KeyCodec.checkKeyPair(
          KeyType.mlDsa65,
          a.key.publicKey,
          a.key.privateKey,
        ),
        returnsNormally,
      );
    });
  });
}
