import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:activeledger/activeledger.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

/// Connection over a real socket: an in-process HttpServer on loopback, so
/// the request the SDK actually puts on the wire and the failures a real
/// transport produces are both exercised. No external network.
class Seen {
  Seen(this.method, this.path, this.contentType, this.body);

  final String method;
  final String path;
  final String? contentType;
  final List<int> body;

  String get text => utf8.decode(body);
}

void main() {
  late HttpServer server;
  late List<Seen> requests;
  late Future<void> Function(HttpRequest) handler;

  Connection connect({http.Client? client}) =>
      Connection.fromUrl('http://127.0.0.1:${server.port}', client: client);

  setUp(() async {
    requests = [];
    handler = (request) async {
      request.response
        ..statusCode = 200
        ..write('{}');
    };
    server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) async {
      final body = await request.fold<List<int>>([], (a, c) => a..addAll(c));
      requests.add(
        Seen(
          request.method,
          request.uri.path,
          request.headers.contentType?.mimeType,
          body,
        ),
      );
      await handler(request);
      await request.response.close();
    });
  });

  tearDown(() => server.close(force: true));

  group('what goes on the wire', () {
    test(
      'a POST of the canonical JSON, key order kept, as UTF-8 with a JSON content type',
      () async {
        final connection = connect();
        addTearDown(connection.close);
        await connection.sendTransaction({
          'b': 1,
          'a': {
            'z': 'café',
            'y': [true, null],
          },
        });

        expect(requests, hasLength(1));
        expect(requests.single.method, 'POST');
        expect(requests.single.contentType, 'application/json');
        expect(
          requests.single.text,
          '{"b":1,"a":{"z":"café","y":[true,null]}}',
        );
      },
    );

    test('a Transaction is sent as its envelope, bytes as signed', () async {
      final ledger = Activeledger('http://127.0.0.1:${server.port}');
      addTearDown(ledger.close);
      final key = ledger.generateKey('k');
      key.identity = 'abc';
      final tx = ledger.transactions.labelledTransaction(
        key: key,
        namespace: 'default',
        contract: 'c',
        inputLabel: 'in',
        stream: 'abc',
        inputData: {'n': 1},
      );
      await ledger.send(tx);

      expect(requests.single.text, canonicalJson(tx.toJson()));
      final sent = jsonDecode(requests.single.text) as Map;
      expect(ledger.keys, isNotNull);
      expect(
        const DefaultCryptoProvider().verify(
          canonicalJson(sent[r'$tx']),
          (sent[r'$sigs'] as Map)['abc'] as String,
          key.key.publicKey,
        ),
        isTrue,
        reason: 'the node can verify what it received',
      );
    });

    test('posts to the path in the URL', () async {
      final connection = Connection.fromUrl(
        'http://127.0.0.1:${server.port}/some/path',
      );
      addTearDown(connection.close);
      await connection.sendTransaction('{}');
      expect(requests.single.path, '/some/path');
    });

    test('the host/port constructor reaches the same server', () async {
      final connection = Connection('http', '127.0.0.1', server.port);
      addTearDown(connection.close);
      await connection.sendTransaction({'x': 1});
      expect(requests.single.text, '{"x":1}');
    });
  });

  group('replies', () {
    test('a committed reply is typed', () async {
      handler = (request) async {
        request.response.write(
          jsonEncode({
            r'$umid': 'u1',
            r'$summary': {'total': 4, 'vote': 4, 'commit': 4},
            r'$streams': {
              'new': [
                {'id': 's1', 'name': 'one'},
              ],
              'updated': [
                {'id': 's2'},
              ],
            },
            r'$responses': ['hi'],
          }),
        );
      };
      final connection = connect();
      addTearDown(connection.close);
      final response = await connection.sendTransaction({'x': 1});

      expect(response.committed, isTrue);
      expect(response.umid, 'u1');
      expect(response.summary.commit, 4);
      expect(response.streams.created.single.toString(), 's1 (one)');
      expect(response.streams.updated.single.id, 's2');
      expect(response.responses, ['hi']);
    });

    test('a rejected transaction is HTTP 200 and is not committed', () async {
      handler = (request) async {
        request.response.write(
          jsonEncode({
            r'$summary': {
              'total': 4,
              'vote': 0,
              'commit': 0,
              'errors': ['Signature Incorrect'],
            },
          }),
        );
      };
      final connection = connect();
      addTearDown(connection.close);
      final response = await connection.sendTransaction({'x': 1});

      expect(response.committed, isFalse);
      expect(response.errors, ['Signature Incorrect']);
    });

    test('a reply with non-ASCII text decodes as UTF-8', () async {
      handler = (request) async {
        request.response.headers.contentType = ContentType(
          'application',
          'json',
        );
        request.response.add(
          utf8.encode(
            jsonEncode({
              r'$responses': ['naïve ☃'],
            }),
          ),
        );
      };
      final connection = connect();
      addTearDown(connection.close);
      final response = await connection.sendTransaction({'x': 1});
      expect(response.responses, ['naïve ☃']);
    });
  });

  group('HTTP error statuses', () {
    for (final status in [400, 404, 500, 503]) {
      test('$status is a LedgerHttpException with status and body', () async {
        handler = (request) async {
          request.response
            ..statusCode = status
            ..write('node said no: $status');
        };
        final connection = connect();
        addTearDown(connection.close);

        await expectLater(
          connection.sendTransaction({'x': 1}),
          throwsA(
            isA<LedgerHttpException>()
                .having((e) => e.statusCode, 'statusCode', status)
                .having((e) => e.body, 'body', 'node said no: $status')
                .having((e) => e.message, 'message', contains('HTTP $status')),
          ),
        );
      });
    }

    test('an error status with an empty body still throws', () async {
      handler = (request) async {
        request.response.statusCode = 502;
      };
      final connection = connect();
      addTearDown(connection.close);
      await expectLater(
        connection.sendTransaction({'x': 1}),
        throwsA(
          isA<LedgerHttpException>()
              .having((e) => e.statusCode, 'statusCode', 502)
              .having((e) => e.body, 'body', isEmpty),
        ),
      );
    });

    test('an error body that is not valid UTF-8 is kept, not fatal', () async {
      handler = (request) async {
        request.response
          ..statusCode = 500
          ..add([0x62, 0x61, 0x64, 0xff, 0xfe]);
      };
      final connection = connect();
      addTearDown(connection.close);
      await expectLater(
        connection.sendTransaction({'x': 1}),
        throwsA(
          isA<LedgerHttpException>().having(
            (e) => e.body,
            'body',
            startsWith('bad'),
          ),
        ),
      );
    });

    test('a 204 with no body is not a ledger response', () async {
      handler = (request) async {
        request.response.statusCode = 204;
      };
      final connection = connect();
      addTearDown(connection.close);
      await expectLater(
        connection.sendTransaction({'x': 1}),
        throwsFormatException,
      );
    });
  });

  group('transport failures', () {
    test('a refused connection is a ClientException', () async {
      // Bind to learn a free port, then close it so nothing listens there.
      final probe = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final port = probe.port;
      await probe.close(force: true);

      final connection = Connection('http', '127.0.0.1', port);
      addTearDown(connection.close);
      await expectLater(
        connection.sendTransaction({'x': 1}),
        throwsA(isA<http.ClientException>()),
      );
    });

    test('a server that hangs up mid-reply is a ClientException', () async {
      handler = (request) async {
        final socket = await request.response.detachSocket(writeHeaders: false);
        socket.destroy();
      };
      final connection = connect();
      addTearDown(connection.close);
      await expectLater(
        connection.sendTransaction({'x': 1}),
        throwsA(isA<http.ClientException>()),
      );
    });

    test('a truncated body is an error, not a half-read response', () async {
      handler = (request) async {
        final socket = await request.response.detachSocket(writeHeaders: false);
        socket.write(
          'HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n{"\$umid":',
        );
        await socket.flush();
        socket.destroy();
      };
      final connection = connect();
      addTearDown(connection.close);
      await expectLater(
        connection.sendTransaction({'x': 1}),
        throwsA(isA<http.ClientException>()),
      );
    });

    test('a 200 with a non-JSON body is a FormatException', () async {
      handler = (request) async {
        request.response.write('<html>proxy error</html>');
      };
      final connection = connect();
      addTearDown(connection.close);
      await expectLater(
        connection.sendTransaction({'x': 1}),
        throwsFormatException,
      );
    });

    test('a 200 with a JSON array is an ActiveledgerException', () async {
      handler = (request) async {
        request.response.write('[1,2]');
      };
      final connection = connect();
      addTearDown(connection.close);
      await expectLater(
        connection.sendTransaction({'x': 1}),
        throwsA(
          isA<ActiveledgerException>().having(
            (e) => e.message,
            'message',
            contains('Unexpected ledger response: [1,2]'),
          ),
        ),
      );
    });
  });

  group('connection lifetime', () {
    test('close releases its own client: further sends fail', () async {
      final connection = connect();
      await connection.sendTransaction({'x': 1});
      connection.close();
      await expectLater(
        connection.sendTransaction({'x': 1}),
        throwsA(isA<http.ClientException>()),
      );
      expect(requests, hasLength(1));
    });

    test('a client passed in survives close and keeps working', () async {
      final client = http.Client();
      addTearDown(client.close);
      final connection = connect(client: client);
      connection.close();
      await connection.sendTransaction({'x': 1});
      expect(requests, hasLength(1));
    });

    test('concurrent sends each get their own reply', () async {
      handler = (request) async {
        request.response.write(jsonEncode({r'$umid': 'echo'}));
      };
      final connection = connect();
      addTearDown(connection.close);
      final responses = await Future.wait([
        for (var i = 0; i < 8; i++) connection.sendTransaction({'i': i}),
      ]);
      expect(responses.map((r) => r.umid), everyElement('echo'));
      expect(requests.map((r) => r.text).toSet(), {
        for (var i = 0; i < 8; i++) '{"i":$i}',
      });
    });
  });

  group('onboardKey against a real socket', () {
    test('sets the identity from the created stream', () async {
      handler = (request) async {
        request.response.write(
          jsonEncode({
            r'$summary': {'total': 1, 'vote': 1, 'commit': 1},
            r'$streams': {
              'new': [
                {'id': 'identity-1'},
              ],
            },
          }),
        );
      };
      final ledger = Activeledger('http://127.0.0.1:${server.port}');
      addTearDown(ledger.close);
      final key = ledger.generateKey('me', type: KeyType.mlDsa65);
      await ledger.onboard(key);

      expect(key.identity, 'identity-1');
      final sent = jsonDecode(requests.single.text) as Map;
      expect((sent[r'$sigs'] as Map).keys, ['me']);
      expect(sent[r'$selfsign'], isTrue);
    });

    test('a rejected onboarding names the ledger errors', () async {
      handler = (request) async {
        request.response.write(
          jsonEncode({
            r'$summary': {
              'errors': ['already exists'],
            },
          }),
        );
      };
      final ledger = Activeledger('http://127.0.0.1:${server.port}');
      addTearDown(ledger.close);
      final key = ledger.generateKey('me');
      await expectLater(
        ledger.onboard(key),
        throwsA(
          isA<OnboardException>().having(
            (e) => e.message,
            'message',
            contains('already exists'),
          ),
        ),
      );
      expect(key.identity, isNull);
    });
  });
}
