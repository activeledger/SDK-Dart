import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

/// One server-sent event.
class ServerSentEvent {
  const ServerSentEvent({this.type = 'message', required this.data, this.id});

  /// The `event:` field, `message` when the server sent none.
  final String type;

  /// The `data:` lines, joined with newlines.
  final String data;

  /// The last `id:` seen, if any.
  final String? id;

  @override
  String toString() =>
      'ServerSentEvent($type, $data${id == null ? '' : ', $id'})';
}

/// An incremental parser for the `text/event-stream` format, fed one line
/// at a time (without its terminator).
///
/// It follows the WHATWG rules that matter in practice:
///
/// - multiple `data:` lines in one event join with newlines - treating them
///   as separate events is the classic SSE bug;
/// - lines starting `:` are comments (heartbeats) and are ignored, not
///   delivered as empty events;
/// - `event:` does not leak into the following event;
/// - one space after the colon is stripped, and no more;
/// - an event still pending when the stream ends is discarded, as a browser
///   `EventSource` discards it.
class SseParser {
  final StringBuffer _data = StringBuffer();
  bool _hasData = false;
  String _type = '';
  String? _lastId;
  int? _retry;

  /// The last event id seen, for `Last-Event-ID` on reconnect.
  String? get lastEventId => _lastId;

  /// The reconnection delay the server asked for, in milliseconds.
  int? get retry => _retry;

  /// Processes one line, returning an event when it completes one.
  ServerSentEvent? addLine(String line) {
    if (line.isEmpty) {
      if (!_hasData) {
        _type = '';
        return null;
      }
      final event = ServerSentEvent(
        type: _type.isEmpty ? 'message' : _type,
        data: _data.toString(),
        id: _lastId,
      );
      _data.clear();
      _hasData = false;
      _type = '';
      return event;
    }
    if (line.startsWith(':')) return null;

    final colon = line.indexOf(':');
    final field = colon == -1 ? line : line.substring(0, colon);
    var value = colon == -1 ? '' : line.substring(colon + 1);
    if (value.startsWith(' ')) value = value.substring(1);

    switch (field) {
      case 'data':
        if (_hasData) _data.write('\n');
        _data.write(value);
        _hasData = true;
      case 'event':
        _type = value;
      case 'id':
        if (!value.contains('\u0000')) _lastId = value;
      case 'retry':
        final ms = int.tryParse(value);
        if (ms != null && ms >= 0) _retry = ms;
    }
    return null;
  }

  /// Discards any partly built event, as at the end of a stream.
  void reset() {
    _data.clear();
    _hasData = false;
    _type = '';
  }
}

/// Access to the events API of an ActiveCore server - by default on port
/// 5261, not the node's 5260.
///
/// Two ways to use it. The callback API matches the JavaScript SDK:
///
/// ```dart
/// final events = LedgerEvents('http://localhost:5261');
/// final id = events.subscribeToActivity((stream) => print(stream));
/// events.unsubscribe(id);
/// ```
///
/// The stream API is more natural in Dart, and cancelling the subscription
/// closes the connection:
///
/// ```dart
/// final sub = events.activity().listen(print);
/// await sub.cancel();
/// ```
///
/// Connections reconnect automatically after a dropped connection or a 5xx,
/// waiting [retryDelay] (or what the server asks for) and resuming from the
/// last event id. Other HTTP errors end the subscription.
class LedgerEvents {
  /// [url] is the ActiveCore address; `/api` is appended if missing.
  ///
  /// [clientFactory] makes a fresh HTTP client per connection, so
  /// cancelling can abort it; tests pass a mock here.
  LedgerEvents(
    String url, {
    http.Client Function()? clientFactory,
    this.retryDelay = const Duration(seconds: 3),
  }) : _clientFactory = clientFactory ?? http.Client.new {
    if (!(url.startsWith('http://') || url.startsWith('https://'))) {
      throw ArgumentError.value(
        url,
        'url',
        'Activecore URL must include http:// or https://',
      );
    }
    var base = url;
    while (base.endsWith('/')) {
      base = base.substring(0, base.length - 1);
    }
    if (!base.endsWith('api')) base = '$base/api';
    this.url = base;
  }

  /// The resolved API base, ending `/api`.
  late final String url;

  /// How long to wait before reconnecting, unless the server says otherwise.
  final Duration retryDelay;

  final http.Client Function() _clientFactory;
  final StreamController<Object> _errors = StreamController.broadcast();
  final Map<int, StreamSubscription<Object?>> _listeners = {};
  int _reference = 1;

  /// Connection and parse errors from subscriptions made with the callback
  /// API - the JavaScript SDK's `errorEvents` `ledgerEventError`.
  Stream<Object> get errors => _errors.stream;

  /// Activity notifications: all activity on the ledger, or activity on
  /// [streamId] only. Each value is the notification's `stream` field.
  Stream<Object?> activity({String? streamId}) => subscribe(
    streamId == null ? 'activity/subscribe' : 'activity/subscribe/$streamId',
  ).map((event) => _field(event, (json) => json['stream']));

  /// Contract events: all of them, those emitted by [contract], or [event]
  /// from [contract]. Each value is the event's `event.data`.
  Stream<Object?> events({String? contract, String? event}) {
    if (event != null && contract == null) {
      throw ArgumentError('Must pass contract to use event');
    }
    var resource = 'events';
    if (contract != null) resource += '/$contract';
    if (event != null) resource += '/$event';
    return subscribe(resource).map(
      (e) => _field(e, (json) {
        final inner = json['event'];
        return inner is Map ? inner['data'] : null;
      }),
    );
  }

  /// Subscribes with [callback] to activity notifications, returning an id
  /// for [unsubscribe]. See [activity].
  int subscribeToActivity(
    void Function(Object? stream) callback, {
    String? streamId,
  }) => _listen(activity(streamId: streamId), callback);

  /// Subscribes with [callback] to contract events, returning an id for
  /// [unsubscribe]. See [events].
  int subscribeToEvent(
    void Function(Object? data) callback, {
    String? contract,
    String? event,
  }) => _listen(events(contract: contract, event: event), callback);

  /// Closes a subscription made with the callback API. Returns false if
  /// there was no such subscription.
  bool unsubscribe(int id) {
    final subscription = _listeners.remove(id);
    if (subscription == null) return false;
    unawaited(subscription.cancel());
    return true;
  }

  /// Closes every callback subscription.
  Future<void> close() async {
    final subscriptions = _listeners.values.toList();
    _listeners.clear();
    await Future.wait(subscriptions.map((s) => s.cancel()));
  }

  /// The raw `message` events from [resource] (a path under `/api`).
  Stream<ServerSentEvent> subscribe(String resource) {
    late StreamController<ServerSentEvent> controller;
    http.Client? client;
    var active = true;
    Timer? wait;
    Completer<void>? waiting;

    Future<void> run() async {
      final parser = SseParser();
      while (active) {
        client = _clientFactory();
        var permanent = false;
        try {
          final request = http.Request('GET', Uri.parse('$url/$resource'))
            ..headers['Accept'] = 'text/event-stream'
            ..headers['Cache-Control'] = 'no-cache';
          final lastId = parser.lastEventId;
          if (lastId != null && lastId.isNotEmpty) {
            request.headers['Last-Event-ID'] = lastId;
          }
          final response = await client!.send(request);
          if (response.statusCode != 200) {
            permanent = response.statusCode < 500;
            await response.stream.drain<void>();
            throw http.ClientException(
              'Event stream returned HTTP ${response.statusCode}',
              request.url,
            );
          }
          await for (final line
              in response.stream
                  .transform(utf8.decoder)
                  .transform(const LineSplitter())) {
            if (!active) break;
            final event = parser.addLine(line);
            if (event != null && event.type == 'message') controller.add(event);
          }
          parser.reset();
        } catch (error, stack) {
          parser.reset();
          if (active) controller.addError(error, stack);
        } finally {
          client?.close();
          client = null;
        }
        if (!active) break;
        if (permanent) {
          await controller.close();
          return;
        }
        final retry = parser.retry;
        waiting = Completer<void>();
        wait = Timer(
          retry == null ? retryDelay : Duration(milliseconds: retry),
          () => waiting?.complete(),
        );
        await waiting!.future;
      }
    }

    controller = StreamController<ServerSentEvent>(
      onListen: () => unawaited(run()),
      onCancel: () {
        active = false;
        wait?.cancel();
        if (waiting != null && !waiting!.isCompleted) waiting!.complete();
        // Aborts the in-flight request, which is the point: a subscriber
        // that goes away must not leave the server holding a connection.
        client?.close();
      },
    );
    return controller.stream;
  }

  int _listen(Stream<Object?> stream, void Function(Object?) callback) {
    final id = _reference++;
    _listeners[id] = stream.listen(
      callback,
      onError: (Object error) => _errors.add(error),
      onDone: () => _listeners.remove(id),
    );
    return id;
  }

  static Object? _field(
    ServerSentEvent event,
    Object? Function(Map<String, Object?>) pick,
  ) {
    final json = jsonDecode(event.data);
    if (json is! Map) {
      throw FormatException('Event data is not a JSON object', event.data);
    }
    return pick(json.cast<String, Object?>());
  }
}
