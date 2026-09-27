import 'dart:convert';

import 'package:activeledger/activeledger.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

void main() {
  final keys = KeyHandler();
  final transactions = TransactionHandler();
  const crypto = DefaultCryptoProvider();

  group('buildOnboardKeyTx', () {
    for (final type in [KeyType.secp256k1, KeyType.mlDsa65]) {
      test('${type.wire}: shape and signature', () {
        final key = keys.generateKey('identity', type: type);
        final tx = transactions.buildOnboardKeyTx(key);

        expect(tx.selfsign, isTrue);
        expect(tx.tx, {
          r'$contract': 'onboard',
          r'$i': {
            'identity': {'publicKey': key.publicKey, 'type': type.wire},
          },
          r'$namespace': 'default',
        });
        // Keyed by the $i label - there is no stream yet.
        expect(tx.sigs.keys, ['identity']);
        expect(
          crypto.verify(
            tx.signedString,
            tx.sigs['identity']!,
            key.publicKey,
            type: type,
          ),
          isTrue,
        );
      });
    }

    test('always keys by label, even for a key with an identity', () {
      final key = keys.generateKey('me')..identity = 'abc';
      expect(transactions.buildOnboardKeyTx(key).sigs.keys, ['me']);
    });

    test('custom contract and namespace', () {
      final key = keys.generateKey('me');
      final tx = transactions.buildOnboardKeyTx(
        key,
        contract: 'mine',
        namespace: 'ns',
      );
      expect(tx.tx[r'$contract'], 'mine');
      expect(tx.tx[r'$namespace'], 'ns');
    });

    test('the envelope serialises as the JavaScript SDK sends it', () {
      final key = keys.generateKey('identity');
      final json = canonicalJson(transactions.buildOnboardKeyTx(key).toJson());
      expect(json, startsWith(r'{"$selfsign":true,"$sigs":{"identity":"'));
      expect(json, contains(r'"$tx":{"$contract":"onboard","$i":{"identity":'));
    });
  });

  group('labelledTransaction', () {
    final key = keys.generateKey('me', type: KeyType.mlDsa65)
      ..identity = 'stream-id';

    test('builds and signs, keyed by identity', () {
      final tx = transactions.labelledTransaction(
        key: key,
        namespace: 'ns',
        contract: 'c',
        inputLabel: 'input',
        stream: 'stream-id',
        inputData: {'amount': 10, 'note': 'hi'},
        entry: 'update',
        outputs: {
          'out': {'x': 1},
        },
        readonly: {'target': 'other-stream'},
      );
      expect(
        canonicalJson(tx.tx),
        r'{"$contract":"c","$i":{"input":{"amount":10,"note":"hi","$stream":"stream-id"}},'
        r'"$namespace":"ns","$entry":"update","$o":{"out":{"x":1}},"$r":{"target":"other-stream"}}',
      );
      expect(tx.selfsign, isNull);
      expect(tx.sigs.keys, ['stream-id']);
      expect(
        crypto.verify(
          tx.signedString,
          tx.sigs['stream-id']!,
          key.publicKey,
          type: key.type,
        ),
        isTrue,
      );
    });

    test('self-signed: carries the key and is keyed by label', () {
      final tx = transactions.labelledTransaction(
        key: key,
        namespace: 'ns',
        contract: 'c',
        inputLabel: 'input',
        stream: 'stream-id',
        selfsign: true,
      );
      final input = (tx.tx[r'$i']! as Map)['input'] as Map;
      expect(input['publicKey'], key.publicKey);
      expect(input['type'], 'ml-dsa-65');
      expect(tx.selfsign, isTrue);
      expect(tx.sigs.keys, ['input']);
    });

    test('requires an identity', () {
      expect(
        () => transactions.labelledTransaction(
          key: keys.generateKey('x'),
          namespace: 'n',
          contract: 'c',
          inputLabel: 'i',
          stream: 's',
        ),
        throwsStateError,
      );
    });
  });

  test('signTransaction adds one signature per signer', () {
    final a = keys.generateKey('a')..identity = 'A';
    final b = keys.generateKey('b', type: KeyType.mlDsa65)..identity = 'B';
    final tx = Transaction(
      tx: {
        r'$namespace': 'ns',
        r'$contract': 'c',
        r'$i': {'A': {}, 'B': {}},
      },
    );
    transactions.signTransaction(tx, a);
    transactions.signTransaction(tx, b);
    expect(tx.sigs.keys, ['A', 'B']);
    expect(
      crypto.verify(tx.signedString, tx.sigs['B']!, b.publicKey, type: b.type),
      isTrue,
    );
  });

  test('Transaction round-trips through JSON', () {
    final key = keys.generateKey('identity');
    final tx = transactions.buildOnboardKeyTx(key);
    final copy = Transaction.fromJson(
      (jsonDecode(tx.toString()) as Map).cast<String, Object?>(),
    );
    expect(copy.toString(), tx.toString());
  });

  group('Connection and onboarding', () {
    test('posts the canonical envelope and parses the response', () async {
      late http.Request seen;
      final client = MockClient((request) async {
        seen = request;
        return http.Response(
          jsonEncode({
            r'$umid': 'umid-1',
            r'$summary': {'total': 4, 'vote': 4, 'commit': 4},
            r'$streams': {
              'new': [
                {'id': 'new-identity', 'name': 'activeledger.default.onboard'},
              ],
              'updated': [],
            },
          }),
          200,
        );
      });
      final connection = Connection('http', 'localhost', 5260, client: client);
      final key = keys.generateKey('identity', type: KeyType.mlDsa65);

      final response = await keys.onboardKey(key, connection);

      expect(seen.url.toString(), 'http://localhost:5260');
      expect(seen.method, 'POST');
      expect(seen.headers['Content-Type'], startsWith('application/json'));
      final body = jsonDecode(seen.body) as Map;
      expect(body[r'$selfsign'], isTrue);
      expect(response.committed, isTrue);
      expect(response.umid, 'umid-1');
      expect(response.summary.commit, 4);
      expect(key.identity, 'new-identity');
    });

    test('a rejected transaction is HTTP 200 and not committed', () async {
      final client = MockClient(
        (_) async => http.Response(
          jsonEncode({
            r'$umid': 'u',
            r'$summary': {
              'total': 4,
              'vote': 0,
              'commit': 0,
              'errors': ['1220 Signature Incorrect'],
            },
            r'$streams': {'new': [], 'updated': []},
          }),
          200,
        ),
      );
      final connection = Connection.fromUrl('http://node:5260', client: client);
      final key = keys.generateKey('identity');

      final response = await connection.sendTransaction(
        transactions.buildOnboardKeyTx(key),
      );
      expect(response.committed, isFalse);
      expect(response.errors, ['1220 Signature Incorrect']);

      expect(
        () => keys.onboardKey(key, connection),
        throwsA(
          isA<OnboardException>().having(
            (e) => e.message,
            'message',
            contains('1220 Signature Incorrect'),
          ),
        ),
      );
    });

    test('non-2xx is an exception', () async {
      final client = MockClient((_) async => http.Response('boom', 500));
      final connection = Connection.fromUrl('http://node:5260', client: client);
      await expectLater(
        connection.sendTransaction({r'$tx': {}}),
        throwsA(
          isA<LedgerHttpException>().having(
            (e) => e.statusCode,
            'statusCode',
            500,
          ),
        ),
      );
    });

    test('responses carry returnToRemote values', () {
      final response = LedgerResponse({
        r'$responses': [
          {'balance': 5},
        ],
      });
      expect(response.responses, [
        {'balance': 5},
      ]);
      expect(response.streams.created, isEmpty);
    });

    test('rejects a URL without http or https', () {
      expect(() => Connection.fromUrl('localhost:5260'), throwsArgumentError);
    });
  });
}
