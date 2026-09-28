import 'dart:async';
import 'dart:convert';

import 'package:activeledger/activeledger.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

List<ServerSentEvent> parse(String text) {
  final parser = SseParser();
  return [
    for (final line in const LineSplitter().convert(text))
      ?parser.addLine(line),
  ];
}

void main() {
  group('SseParser', () {
    test('joins multiple data lines with newlines', () {
      final events = parse('data: one\ndata: two\n\n');
      expect(events.single.data, 'one\ntwo');
    });

    test('ignores comments and heartbeats', () {
      expect(parse(': heartbeat\n\n:\n\n'), isEmpty);
    });

    test('event type does not leak into the next event', () {
      final events = parse('event: custom\ndata: a\n\ndata: b\n\n');
      expect(events.map((e) => e.type), ['custom', 'message']);
    });

    test('strips exactly one leading space', () {
      expect(parse('data:  two spaces\n\n').single.data, ' two spaces');
      expect(parse('data:none\n\n').single.data, 'none');
    });

    test('tracks id and retry', () {
      final parser = SseParser();
      for (final line in ['id: 7', 'retry: 1500', 'data: x', '']) {
        parser.addLine(line);
      }
      expect(parser.lastEventId, '7');
      expect(parser.retry, 1500);
    });

    test('a blank line with no data dispatches nothing', () {
      expect(parse('event: x\n\n'), isEmpty);
    });
  });

  group('LedgerEvents (storage)', () {
    // Frames exactly as the storage engine writes them (storage/src/sse.ts).
    String frame(String id, Map<String, Object?> doc) =>
        'id:$id\nevent: message\ndata:${jsonEncode(doc)}\n\n';

    test('builds the feed URL', () {
      expect(
        LedgerEvents('http://host:5259').url,
        'http://host:5259/activeledgerevents/events',
      );
      expect(
        LedgerEvents('http://host:5259/', database: 'myevents').url,
        'http://host:5259/myevents/events',
      );
      expect(() => LedgerEvents('host:5259'), throwsArgumentError);
    });

    test('parses events and filters by contract and name', () async {
      final requests = <Uri>[];
      final events = LedgerEvents(
        'http://host:5259',
        clientFactory: () => _sse(requests, [
          ':\n\n',
          frame('1700000000000-1,umid-a', {
            'name': 'transfer',
            'data': {'amount': 1},
            'phase': 'commit',
            'contract': 'other',
          }),
          frame('1700000000001-2,umid-b', {
            'name': 'mint',
            'data': {'amount': 2},
            'phase': 'commit',
            'contract': 'token',
          }),
          frame('1700000000002-3,umid-c', {
            'name': 'transfer',
            'data': {'amount': 3},
            'phase': 'commit',
            'contract': 'token',
          }),
        ]),
      );

      final all = await events.events().take(3).toList();
      expect(all.map((e) => e.name), ['transfer', 'mint', 'transfer']);
      expect(all.first.umid, 'umid-a');
      expect(all.first.phase, 'commit');
      expect(
        all.first.time,
        DateTime.fromMillisecondsSinceEpoch(1700000000000),
      );
      expect(
        requests.first.toString(),
        'http://host:5259/activeledgerevents/events',
      );

      final filtered = await events
          .events(contract: 'token', event: 'transfer')
          .first;
      expect(filtered.data, {'amount': 3});
    });

    test('callback API receives data', () async {
      final events = LedgerEvents(
        'http://host:5259',
        clientFactory: () => _sse([], [
          frame('1-1,u', {'name': 'n', 'data': 'payload', 'contract': 'c'}),
        ]),
      );
      final received = Completer<Object?>();
      final id = events.subscribeToEvent(received.complete, contract: 'c');
      expect(await received.future, 'payload');
      expect(events.unsubscribe(id), isTrue);
      expect(events.unsubscribe(id), isFalse);
    });

    test('reconnects, sending the last event id', () async {
      final seen = <String?>[];
      var connection = 0;
      final events = LedgerEvents(
        'http://host:5259',
        retryDelay: const Duration(milliseconds: 10),
        clientFactory: () => MockClient.streaming((request, _) async {
          seen.add(request.headers['Last-Event-ID']);
          connection++;
          final body = connection == 1
              ? frame('5-1,u1', {'name': 'a', 'data': 1})
              : frame('6-1,u2', {'name': 'b', 'data': 2});
          return http.StreamedResponse(Stream.value(utf8.encode(body)), 200);
        }),
      );
      final values = await events.events().take(2).toList();
      expect(values.map((e) => e.data), [1, 2]);
      expect(seen, [null, '5-1,u1']);
    });

    test('Activeledger derives the storage URL from the node URL', () {
      final ledger = Activeledger('http://node:5260');
      expect(ledger.storageUrl, 'http://node:5259');
      expect(ledger.events.url, 'http://node:5259/activeledgerevents/events');
      expect(
        Activeledger(
          'http://node:5260',
          storageUrl: 'http://db:9000',
        ).storageUrl,
        'http://db:9000',
      );
    });
  });

  group('ActiveCoreEvents (legacy)', () {
    test('resolves the api base URL', () {
      expect(ActiveCoreEvents('http://host:5261').url, 'http://host:5261/api');
      expect(ActiveCoreEvents('http://host:5261/').url, 'http://host:5261/api');
      expect(ActiveCoreEvents('https://host/api').url, 'https://host/api');
      expect(() => ActiveCoreEvents('host:5261'), throwsArgumentError);
    });

    test('activity delivers the stream field', () async {
      final requests = <Uri>[];
      final events = ActiveCoreEvents(
        'http://host:5261',
        clientFactory: () => _sse(requests, [
          ': hello\n',
          'data: {"stream":{"id":"s1"}}\n\n',
          'event: other\ndata: {"stream":"ignored"}\n\n',
          'data: {"stream":',
          '{"id":"s2"}}\n\n',
        ]),
      );

      final values = await events.activity(streamId: 's1').take(2).toList();
      expect(values, [
        {'id': 's1'},
        {'id': 's2'},
      ]);
      expect(
        requests.first.toString(),
        'http://host:5261/api/activity/subscribe/s1',
      );
    });

    test('contract events deliver event.data', () async {
      final requests = <Uri>[];
      final events = ActiveCoreEvents(
        'http://host:5261',
        clientFactory: () =>
            _sse(requests, ['data: {"event":{"data":{"n":1}}}\n\n']),
      );
      final value = await events.events(contract: 'c', event: 'e').first;
      expect(value, {'n': 1});
      expect(requests.single.path, '/api/events/c/e');
      expect(() => events.events(event: 'e'), throwsArgumentError);
    });

    test('callback API subscribes and unsubscribes', () async {
      final events = ActiveCoreEvents(
        'http://host:5261',
        clientFactory: () => _sse([], ['data: {"stream":"x"}\n\n']),
      );
      final received = Completer<Object?>();
      final id = events.subscribeToActivity(received.complete);
      expect(await received.future, 'x');
      expect(events.unsubscribe(id), isTrue);
      expect(events.unsubscribe(id), isFalse);
    });

    test('reconnects after the stream ends, sending Last-Event-ID', () async {
      final seen = <String?>[];
      var connection = 0;
      final events = ActiveCoreEvents(
        'http://host:5261',
        retryDelay: const Duration(milliseconds: 10),
        clientFactory: () => MockClient.streaming((request, _) async {
          seen.add(request.headers['Last-Event-ID']);
          connection++;
          final body = connection == 1
              ? 'id: 41\ndata: {"stream":1}\n\n'
              : 'data: {"stream":2}\n\n';
          return http.StreamedResponse(Stream.value(utf8.encode(body)), 200);
        }),
      );
      final values = await events.activity().take(2).toList();
      expect(values, [1, 2]);
      expect(seen, [null, '41']);
    });

    test('a 4xx ends the subscription with an error', () async {
      final events = ActiveCoreEvents(
        'http://host:5261',
        clientFactory: () => MockClient((_) async => http.Response('no', 404)),
      );
      await expectLater(
        events.activity(),
        emitsInOrder([emitsError(anything), emitsDone]),
      );
    });

    test('malformed data goes to errors, not the callback', () async {
      final events = ActiveCoreEvents(
        'http://host:5261',
        clientFactory: () => _sse([], ['data: not json\n\n']),
      );
      final error = events.errors.first;
      events.subscribeToEvent((_) => fail('should not be called'));
      expect(await error, isA<FormatException>());
      await events.close();
    });
  });
}

/// A client whose one response streams [chunks] and then stays open.
http.Client _sse(List<Uri> requests, List<String> chunks) =>
    MockClient.streaming((request, _) async {
      requests.add(request.url);
      final controller = StreamController<List<int>>();
      for (final chunk in chunks) {
        controller.add(utf8.encode(chunk));
      }
      return http.StreamedResponse(controller.stream, 200);
    });
