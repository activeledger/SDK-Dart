import 'dart:convert';

import 'package:activeledger/activeledger.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

void main() {
  final keys = KeyHandler();
  final transactions = TransactionHandler();
  const crypto = DefaultCryptoProvider();

  group('LedgerResponse.committed', () {
    test('is false when errors are reported, whatever commit says', () {
      final response = LedgerResponse({
        r'$summary': {
          'commit': 4,
          'errors': ['boom'],
        },
      });
      expect(response.committed, isFalse);
    });

    test('does not look at the commit count', () {
      expect(
        LedgerResponse({
          r'$summary': {'total': 4, 'vote': 4, 'commit': 0},
        }).committed,
        isTrue,
      );
    });

    test('an empty errors list is still committed', () {
      expect(
        LedgerResponse({
          r'$summary': {'commit': 1, 'errors': <String>[]},
        }).committed,
        isTrue,
      );
    });

    test('is false without a summary object', () {
      expect(LedgerResponse({}).committed, isFalse);
      expect(LedgerResponse({r'$umid': 'u'}).committed, isFalse);
      expect(LedgerResponse({r'$summary': 'ok'}).committed, isFalse);
      expect(LedgerResponse({r'$summary': null}).committed, isFalse);
    });

    test('is false when errors is not a list', () {
      expect(
        LedgerResponse({
          r'$summary': {'commit': 1, 'errors': 'boom'},
        }).committed,
        isFalse,
      );
    });

    test('is true when commit is absent and there are no errors', () {
      expect(
        LedgerResponse({
          r'$summary': {'total': 1},
        }).committed,
        isTrue,
      );
    });

    test('tolerates a response with no summary at all', () {
      final response = LedgerResponse({});
      expect(response.committed, isFalse);
      expect(response.errors, isEmpty);
      expect(response.umid, isNull);
      expect(response.responses, isEmpty);
      expect(response.streams.updated, isEmpty);
      expect(response.debug, isNull);
    });

    test('non-string errors are kept as JSON, not dropped', () {
      final response = LedgerResponse({
        r'$summary': {
          'errors': [
            'plain',
            {'code': 1220},
          ],
        },
      });
      expect(response.errors, ['plain', '{"code":1220}']);
      expect(response.committed, isFalse);
    });

    test('numeric fields accept doubles', () {
      final summary = LedgerSummary({'total': 4.0, 'vote': 3, 'commit': 2.0});
      expect([summary.total, summary.vote, summary.commit], [4, 3, 2]);
    });

    test('accessors never throw on wrongly typed fields', () {
      final response = LedgerResponse({
        r'$umid': 5,
        r'$responses': 'nope',
        r'$summary': {'total': 'x', 'vote': [], 'commit': 'y', 'errors': 'e'},
        r'$streams': {
          'new': [
            {'id': 7, 'name': 8},
            {'id': 'a', 'name': 9},
          ],
          'updated': 'x',
        },
      });
      expect(response.umid, isNull);
      expect(response.responses, isEmpty);
      expect(response.summary.total, isNull);
      expect(response.summary.vote, isNull);
      expect(response.summary.commit, isNull);
      expect(response.errors, ['e']);
      expect(response.streams.created.map((s) => s.id), ['a']);
      expect(response.streams.created.single.name, isNull);
      expect(response.streams.updated, isEmpty);
      expect(() => response.committed, returnsNormally);
    });

    test('indexing and toString expose the raw response', () {
      final response = LedgerResponse({r'$umid': 'u', 'extra': 1});
      expect(response['extra'], 1);
      expect(jsonDecode(response.toString()), {r'$umid': 'u', 'extra': 1});
    });
  });

  group('LedgerStreams', () {
    test('parses created and updated streams, with and without names', () {
      final streams = LedgerStreams({
        'new': [
          {'id': 'a', 'name': 'first'},
          {'id': 'b'},
        ],
        'updated': [
          {'id': 'c', 'name': 'third'},
        ],
      });
      expect(streams.created.map((s) => s.id), ['a', 'b']);
      expect(streams.created.map((s) => s.name), ['first', null]);
      expect(streams.updated.single.id, 'c');
      expect(streams.created.first.toString(), 'a (first)');
      expect(streams.created.last.toString(), 'b');
    });

    test('ignores entries that are not objects', () {
      final streams = LedgerStreams({
        'new': [
          'junk',
          {'id': 'a'},
        ],
        'updated': 'not a list',
      });
      expect(streams.created.map((s) => s.id), ['a']);
      expect(streams.updated, isEmpty);
    });
  });

  group('Connection.sendTransaction', () {
    late http.Request seen;
    Connection connect() => Connection.fromUrl(
      'http://node:5260',
      client: MockClient((request) async {
        seen = request;
        return http.Response(jsonEncode({r'$umid': 'u'}), 200);
      }),
    );

    test('sends a Transaction as its canonical envelope', () async {
      final key = keys.generateKey('me');
      final tx = transactions.buildOnboardKeyTx(key);
      await connect().sendTransaction(tx);
      expect(seen.body, canonicalJson(tx.toJson()));
      expect(seen.bodyBytes, utf8.encode(tx.toString()));
    });

    test('sends a Map in canonical form, preserving key order', () async {
      await connect().sendTransaction({
        r'$tx': {'z': 1, 'a': 2},
      });
      expect(seen.body, r'{"$tx":{"z":1,"a":2}}');
    });

    test('sends a String verbatim', () async {
      const raw = r'{ "$tx" : {"b":1,"a":2} }';
      await connect().sendTransaction(raw);
      expect(seen.body, raw);
    });

    test('sends non-ASCII as UTF-8 bytes', () async {
      await connect().sendTransaction({
        r'$tx': {'name': 'café'},
      });
      expect(seen.bodyBytes, utf8.encode('{"\$tx":{"name":"café"}}'));
    });

    test('a 2xx that is not an object is an ActiveledgerException', () async {
      final connection = Connection.fromUrl(
        'http://node:5260',
        client: MockClient((_) async => http.Response('[1,2]', 200)),
      );
      await expectLater(
        connection.sendTransaction({r'$tx': {}}),
        throwsA(isA<ActiveledgerException>()),
      );
    });

    test('a 2xx that is not JSON is an ActiveledgerException', () async {
      final connection = Connection.fromUrl(
        'http://node:5260',
        client: MockClient((_) async => http.Response('<html>', 200)),
      );
      await expectLater(
        connection.sendTransaction({r'$tx': {}}),
        throwsA(isA<ActiveledgerException>()),
      );
    });

    test('a 200 with a body that has no summary is not committed', () async {
      for (final body in ['{}', r'{"$umid":"u"}']) {
        final connection = Connection.fromUrl(
          'http://node:5260',
          client: MockClient((_) async => http.Response(body, 200)),
        );
        final response = await connection.sendTransaction({r'$tx': {}});
        expect(response.committed, isFalse, reason: body);
      }
    });

    test('a non-2xx carries the status and the body', () async {
      final connection = Connection.fromUrl(
        'http://node:5260',
        client: MockClient((_) async => http.Response('bad gateway', 502)),
      );
      await expectLater(
        connection.sendTransaction({r'$tx': {}}),
        throwsA(
          isA<LedgerHttpException>()
              .having((e) => e.statusCode, 'statusCode', 502)
              .having((e) => e.body, 'body', 'bad gateway')
              .having((e) => e.toString(), 'toString', contains('502')),
        ),
      );
    });

    test('a 3xx is also an error, not a response', () async {
      final connection = Connection.fromUrl(
        'http://node:5260',
        client: MockClient((_) async => http.Response('{}', 302)),
      );
      await expectLater(
        connection.sendTransaction({r'$tx': {}}),
        throwsA(isA<LedgerHttpException>()),
      );
    });
  });

  group('Connection construction', () {
    test('the protocol/address/port form builds the same URI', () {
      final connection = Connection('https', 'node.example', 443);
      expect(connection.baseUri, Uri.parse('https://node.example:443'));
      connection.close();
    });

    test('rejects other schemes', () {
      expect(() => Connection.fromUrl('ftp://node:5260'), throwsArgumentError);
    });

    test('does not close a client it was given', () {
      final client = _TrackingClient();
      Connection.fromUrl('http://node:5260', client: client).close();
      expect(client.closed, isFalse);
    });
  });

  group('onboardKey', () {
    test('uses the first created stream as the identity', () async {
      final connection = Connection.fromUrl(
        'http://node:5260',
        client: MockClient(
          (_) async => http.Response(
            jsonEncode({
              r'$summary': {'total': 1, 'vote': 1, 'commit': 1},
              r'$streams': {
                'new': [
                  {'id': 'first'},
                  {'id': 'second'},
                ],
              },
            }),
            200,
          ),
        ),
      );
      final key = keys.generateKey('me');
      await keys.onboardKey(key, connection);
      expect(key.identity, 'first');
    });

    test('sends the requested contract and namespace', () async {
      late Map<String, Object?> sent;
      final connection = Connection.fromUrl(
        'http://node:5260',
        client: MockClient((request) async {
          sent = jsonDecode(request.body) as Map<String, Object?>;
          return http.Response(
            jsonEncode({
              r'$streams': {
                'new': [
                  {'id': 's'},
                ],
              },
            }),
            200,
          );
        }),
      );
      await keys.onboardKey(
        keys.generateKey('me'),
        connection,
        contract: 'custom',
        namespace: 'ns',
      );
      final tx = sent[r'$tx']! as Map;
      expect(tx[r'$contract'], 'custom');
      expect(tx[r'$namespace'], 'ns');
    });

    test('a failed onboard leaves the identity unset', () async {
      final connection = Connection.fromUrl(
        'http://node:5260',
        client: MockClient((_) async => http.Response('{}', 200)),
      );
      final key = keys.generateKey('me');
      await expectLater(
        keys.onboardKey(key, connection),
        throwsA(
          isA<OnboardException>()
              .having(
                (e) => e.response,
                'response',
                isA<Map<String, Object?>>(),
              )
              .having((e) => e.message, 'message', contains('"me"'))
              .having((e) => e.toString(), 'toString', startsWith('Onboard')),
        ),
      );
      expect(key.identity, isNull);
    });
  });

  group('Activeledger facade', () {
    test('facade handlers onboard and send against a mock node', () async {
      final requests = <http.Request>[];
      final connection = Connection.fromUrl(
        'http://node:5260',
        client: MockClient((request) async {
          requests.add(request);
          return http.Response(
            jsonEncode({
              r'$summary': {'commit': 1},
              r'$streams': {
                'new': [
                  {'id': 'identity-1'},
                ],
              },
            }),
            200,
          );
        }),
      );
      final ledger = Activeledger('http://node:5260');
      // The facade builds its own Connection; exercise its parts against the
      // mock one instead of the network.
      final key = ledger.generateKey('me', type: KeyType.mlDsa65);
      expect(key.type, KeyType.mlDsa65);
      await ledger.keys.onboardKey(key, connection);
      final tx = ledger.transactions.labelledTransaction(
        key: key,
        namespace: 'default',
        contract: 'c',
        inputLabel: 'in',
        stream: key.identity!,
      );
      final response = await connection.sendTransaction(tx);
      expect(response.committed, isTrue);
      expect(requests, hasLength(2));
      expect(
        (jsonDecode(requests.last.body) as Map)[r'$sigs'],
        containsPair('identity-1', tx.sigs['identity-1']),
      );
      await ledger.close();
    });

    test('rejects a bad node URL', () {
      expect(() => Activeledger('node:5260'), throwsArgumentError);
    });

    test('a custom CryptoProvider is used for signing', () {
      final ledger = Activeledger('http://node:5260', crypto: _FixedCrypto());
      final key = ledger.generateKey('me')..identity = 'id';
      final tx = ledger.transactions.labelledTransaction(
        key: key,
        namespace: 'n',
        contract: 'c',
        inputLabel: 'i',
        stream: 'id',
      );
      expect(tx.sigs['id'], 'fixed-signature');
      expect(ledger.payloads.sign({'a': 1}, key), 'fixed-signature');
    });
  });

  group(r'manual $expire', () {
    final key = keys.generateKey('me')..identity = 'stream-id';

    Transaction expiring(String? expire) {
      final tx = Transaction(
        tx: {
          r'$namespace': 'default',
          r'$contract': 'c',
          r'$expire': ?expire,
          r'$i': {
            'in': {r'$stream': 'stream-id'},
          },
        },
      );
      return transactions.signTransaction(tx, key);
    }

    test('is part of the signed string, in the position it was added', () {
      final tx = expiring('2030-01-01T00:00:00.000Z');
      expect(
        tx.signedString,
        r'{"$namespace":"default","$contract":"c",'
        r'"$expire":"2030-01-01T00:00:00.000Z","$i":{"in":{"$stream":"stream-id"}}}',
      );
    });

    test('is covered by the signature: changing it breaks verification', () {
      final tx = expiring('2030-01-01T00:00:00.000Z');
      final signature = tx.sigs['stream-id']!;
      expect(crypto.verify(tx.signedString, signature, key.publicKey), isTrue);
      tx.tx[r'$expire'] = '2031-01-01T00:00:00.000Z';
      expect(crypto.verify(tx.signedString, signature, key.publicKey), isFalse);
    });

    test('differs from a transaction without it', () {
      expect(
        expiring('2030-01-01T00:00:00.000Z').sigs['stream-id'],
        isNot(expiring(null).sigs['stream-id']),
      );
    });

    test('survives the envelope round trip byte for byte', () {
      final tx = expiring('2030-01-01T00:00:00.000Z');
      final back = Transaction.fromJson(
        jsonDecode(tx.toString()) as Map<String, Object?>,
      );
      expect(back.signedString, tx.signedString);
      expect(back.sigs, tx.sigs);
    });
  });

  group('Transaction', () {
    test(r'fromJson requires $tx', () {
      expect(() => Transaction.fromJson({r'$sigs': {}}), throwsFormatException);
      expect(
        () => Transaction.fromJson({r'$tx': 'not a map'}),
        throwsFormatException,
      );
    });

    test(r'fromJson reads $selfsign and $sigs when present', () {
      final tx = Transaction.fromJson({
        r'$tx': {'a': 1},
        r'$sigs': {'s': 'sig'},
        r'$selfsign': true,
      });
      expect(tx.selfsign, isTrue);
      expect(tx.sigs, {'s': 'sig'});
    });

    test(r'toJson omits $selfsign unless set', () {
      final tx = Transaction(tx: {'a': 1});
      expect(tx.toJson().containsKey(r'$selfsign'), isFalse);
      tx.selfsign = false;
      expect(tx.toJson()[r'$selfsign'], isFalse);
    });

    test('editing tx after signing invalidates the signature', () {
      final key = keys.generateKey('me');
      final tx = transactions.signTransaction(Transaction(tx: {'a': 1}), key);
      final signature = tx.sigs['me']!;
      tx.tx['a'] = 2;
      expect(crypto.verify(tx.signedString, signature, key.publicKey), isFalse);
    });

    test('key order changes the signed string', () {
      expect(
        Transaction(tx: {'a': 1, 'b': 2}).signedString,
        isNot(Transaction(tx: {'b': 2, 'a': 1}).signedString),
      );
    });
  });

  group('signTransaction and signString', () {
    test('keys by identity, falling back to the key name', () {
      final named = keys.generateKey('named');
      expect(
        transactions.signTransaction(Transaction(tx: {}), named).sigs.keys,
        ['named'],
      );
      final onboarded = keys.generateKey('named')..identity = 'stream';
      expect(
        transactions.signTransaction(Transaction(tx: {}), onboarded).sigs.keys,
        ['stream'],
      );
    });

    test('an explicit label wins over the identity', () {
      final key = keys.generateKey('k')..identity = 'stream';
      final tx = transactions.signTransaction(
        Transaction(tx: {}),
        key,
        selfSignLabel: 'label',
      );
      expect(tx.sigs.keys, ['label']);
    });

    test('signing the same signer twice replaces its signature', () {
      final key = keys.generateKey('k', type: KeyType.mlDsa65);
      final tx = Transaction(tx: {'a': 1});
      transactions.signTransaction(tx, key);
      final first = tx.sigs['k'];
      transactions.signTransaction(tx, key);
      expect(tx.sigs, hasLength(1));
      expect(tx.sigs['k'], isNot(first)); // ml-dsa-65 is hedged
    });

    test('signString verifies and is deterministic for secp256k1', () {
      final key = keys.generateKey('k');
      final signature = transactions.signString('hello', key);
      expect(crypto.verify('hello', signature, key.publicKey), isTrue);
      expect(crypto.verify('hellO', signature, key.publicKey), isFalse);
      expect(transactions.signString('hello', key), signature);
    });
  });

  group('labelledTransaction optional parts', () {
    final key = keys.generateKey('me')..identity = 'stream-id';

    test(r'omits $entry, $o and $r when not given', () {
      final tx = transactions.labelledTransaction(
        key: key,
        namespace: 'ns',
        contract: 'c',
        inputLabel: 'in',
        stream: 'stream-id',
      );
      expect(
        tx.signedString,
        r'{"$contract":"c","$i":{"in":{"$stream":"stream-id"}},"$namespace":"ns"}',
      );
    });

    test(r'$stream wins over a $stream in inputData', () {
      final tx = transactions.labelledTransaction(
        key: key,
        namespace: 'ns',
        contract: 'c',
        inputLabel: 'in',
        stream: 'real',
        inputData: {r'$stream': 'spoofed'},
      );
      expect(((tx.tx[r'$i']! as Map)['in'] as Map)[r'$stream'], 'real');
    });

    test('does not mutate the inputData it is given', () {
      final data = <String, Object?>{'a': 1};
      transactions.labelledTransaction(
        key: key,
        namespace: 'ns',
        contract: 'c',
        inputLabel: 'in',
        stream: 'stream-id',
        selfsign: true,
        inputData: data,
      );
      expect(data, {'a': 1});
    });

    test('self-signed signature verifies under the label', () {
      final tx = transactions.labelledTransaction(
        key: key,
        namespace: 'ns',
        contract: 'c',
        inputLabel: 'in',
        stream: 'stream-id',
        selfsign: true,
      );
      expect(
        crypto.verify(tx.signedString, tx.sigs['in']!, key.publicKey),
        isTrue,
      );
      expect(tx.sigs.containsKey('stream-id'), isFalse);
    });
  });
}

class _TrackingClient extends http.BaseClient {
  bool closed = false;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) =>
      throw UnimplementedError();

  @override
  void close() => closed = true;
}

class _FixedCrypto extends DefaultCryptoProvider {
  @override
  String sign(
    String data,
    String privateKey, {
    KeyType type = KeyType.secp256k1,
  }) => 'fixed-signature';
}
