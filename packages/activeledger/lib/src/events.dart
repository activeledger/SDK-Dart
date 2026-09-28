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

/// One contract event, as the storage engine records it.
///
/// Contracts raise these with `this.event.emit(name, data)`. Each is stored
/// as a document in the node's events database and streamed from there.
class LedgerEvent {
  const LedgerEvent({
    required this.id,
    required this.name,
    required this.data,
    this.phase,
    this.contract,
  });

  /// Builds an event from an SSE frame of the storage engine's feed.
  factory LedgerEvent.fromServerSentEvent(ServerSentEvent event) {
    final json = jsonDecode(event.data);
    if (json is! Map) {
      throw FormatException('Event data is not a JSON object', event.data);
    }
    return LedgerEvent(
      id: event.id ?? '',
      name: json['name'] as String? ?? '',
      data: json['data'],
      phase: json['phase'] as String?,
      contract: json['contract'] as String?,
    );
  }

  /// The event id, `<milliseconds>-<counter>,<umid>`. Also what a
  /// reconnection resumes from.
  final String id;

  /// The name the contract gave the event.
  final String name;

  /// The payload the contract emitted.
  final Object? data;

  /// The transaction phase it was emitted in, usually `commit`.
  final String? phase;

  /// The `$contract` of the transaction that raised it - a contract name or
  /// stream id, as the transaction gave it.
  final String? contract;

  /// The transaction's umid, from [id].
  String? get umid {
    final comma = id.indexOf(',');
    return comma == -1 ? null : id.substring(comma + 1);
  }

  /// When the node recorded the event, from [id].
  DateTime? get time {
    final dash = id.indexOf('-');
    final ms = int.tryParse(dash == -1 ? '' : id.substring(0, dash));
    return ms == null ? null : DateTime.fromMillisecondsSinceEpoch(ms);
  }

  @override
  String toString() => 'LedgerEvent($name, ${jsonEncode(data)})';
}

/// Contract events, streamed straight from a node's self-hosted database.
///
/// Every node records the events raised by the transactions it commits, and
/// serves them as server-sent events at `<storage>/<database>/events` - by
/// default `http://<node host>:5259/activeledgerevents/events`, one port
/// below the node's.
///
/// ```dart
/// final events = LedgerEvents('http://localhost:5259');
///
/// // As a stream - cancelling closes the connection.
/// final sub = events.events(contract: 'mycontract').listen((e) {
///   print('${e.name}: ${e.data}');
/// });
///
/// // Or with a callback, as in the JavaScript SDK.
/// final id = events.subscribeToEvent((data) => print(data), event: 'transfer');
/// events.unsubscribe(id);
/// ```
///
/// Connections reconnect automatically after a dropped connection or a 5xx,
/// waiting [retryDelay] (or what the server asks for) and sending the last
/// event id. Other HTTP errors end the subscription.
class LedgerEvents {
  /// [storageUrl] is the node's storage address; [database] is the events
  /// database, `activeledgerevents` unless the node's config says otherwise.
  ///
  /// [clientFactory] makes a fresh HTTP client per connection, so
  /// cancelling can abort it; tests pass a mock here.
  LedgerEvents(
    String storageUrl, {
    this.database = 'activeledgerevents',
    http.Client Function()? clientFactory,
    this.retryDelay = const Duration(seconds: 3),
  }) : url = '${_base(storageUrl, 'Storage')}/$database/events',
       _sse = _SseSource(clientFactory ?? http.Client.new, retryDelay);

  /// The events database.
  final String database;

  /// The full events feed URL.
  final String url;

  /// How long to wait before reconnecting, unless the server says otherwise.
  final Duration retryDelay;

  final _SseSource _sse;

  /// Connection and parse errors from subscriptions made with the callback
  /// API - the JavaScript SDK's `errorEvents` `ledgerEventError`.
  Stream<Object> get errors => _sse.errors;

  /// Contract events: all of them, or only those raised by [contract]
  /// and/or named [event].
  Stream<LedgerEvent> events({String? contract, String? event}) => _sse
      .subscribe(url)
      .map(LedgerEvent.fromServerSentEvent)
      .where(
        (e) =>
            (contract == null || e.contract == contract) &&
            (event == null || e.name == event),
      );

  /// Subscribes with [callback] to contract events, returning an id for
  /// [unsubscribe]. The callback receives each event's `data`, as in the
  /// JavaScript SDK; use [events] for the name, contract and umid as well.
  int subscribeToEvent(
    void Function(Object? data) callback, {
    String? contract,
    String? event,
  }) => _sse.listen(
    events(contract: contract, event: event).map((e) => e.data),
    callback,
  );

  /// The raw server-sent events.
  Stream<ServerSentEvent> raw() => _sse.subscribe(url);

  /// Closes a subscription made with the callback API. Returns false if
  /// there was no such subscription.
  bool unsubscribe(int id) => _sse.unsubscribe(id);

  /// Closes every callback subscription.
  Future<void> close() => _sse.close();
}

/// The events API of an ActiveCore server - by default on port 5261.
///
/// **Legacy.** ActiveCore is no longer part of a typical deployment; contract
/// events come from the node's own database through [LedgerEvents]. This
/// remains for networks that still run ActiveCore, and for its activity
/// feed, which has no storage equivalent.
class ActiveCoreEvents {
  /// [url] is the ActiveCore address; `/api` is appended if missing.
  ActiveCoreEvents(
    String url, {
    http.Client Function()? clientFactory,
    this.retryDelay = const Duration(seconds: 3),
  }) : url = _withApi(_base(url, 'Activecore')),
       _sse = _SseSource(clientFactory ?? http.Client.new, retryDelay);

  /// The resolved API base, ending `/api`.
  final String url;

  /// How long to wait before reconnecting, unless the server says otherwise.
  final Duration retryDelay;

  final _SseSource _sse;

  /// Connection and parse errors from subscriptions made with the callback
  /// API.
  Stream<Object> get errors => _sse.errors;

  /// Activity notifications: all activity on the ledger, or activity on
  /// [streamId] only. Each value is the notification's `stream` field.
  Stream<Object?> activity({String? streamId}) => _sse
      .subscribe(
        streamId == null
            ? '$url/activity/subscribe'
            : '$url/activity/subscribe/$streamId',
      )
      .map((event) => _field(event, (json) => json['stream']));

  /// Contract events: all of them, those emitted by [contract], or [event]
  /// from [contract]. Each value is the event's `event.data`.
  Stream<Object?> events({String? contract, String? event}) {
    if (event != null && contract == null) {
      throw ArgumentError('Must pass contract to use event');
    }
    var resource = 'events';
    if (contract != null) resource += '/$contract';
    if (event != null) resource += '/$event';
    return _sse
        .subscribe('$url/$resource')
        .map(
          (e) => _field(e, (json) {
            final inner = json['event'];
            return inner is Map ? inner['data'] : null;
          }),
        );
  }

  /// Subscribes with [callback] to activity notifications. See [activity].
  int subscribeToActivity(
    void Function(Object? stream) callback, {
    String? streamId,
  }) => _sse.listen(activity(streamId: streamId), callback);

  /// Subscribes with [callback] to contract events. See [events].
  int subscribeToEvent(
    void Function(Object? data) callback, {
    String? contract,
    String? event,
  }) => _sse.listen(events(contract: contract, event: event), callback);

  /// Closes a subscription made with the callback API.
  bool unsubscribe(int id) => _sse.unsubscribe(id);

  /// Closes every callback subscription.
  Future<void> close() => _sse.close();

  static String _withApi(String base) =>
      base.endsWith('/api') ? base : '$base/api';

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

String _base(String url, String what) {
  if (!(url.startsWith('http://') || url.startsWith('https://'))) {
    throw ArgumentError.value(
      url,
      'url',
      '$what URL must include http:// or https://',
    );
  }
  var base = url;
  while (base.endsWith('/')) {
    base = base.substring(0, base.length - 1);
  }
  return base;
}

/// Reconnecting SSE connections, plus the id-keyed callback subscriptions
/// both event classes offer.
class _SseSource {
  _SseSource(this._clientFactory, this._retryDelay);

  final http.Client Function() _clientFactory;
  final Duration _retryDelay;
  final StreamController<Object> _errors = StreamController.broadcast();
  final Map<int, StreamSubscription<Object?>> _listeners = {};
  int _reference = 1;

  Stream<Object> get errors => _errors.stream;

  int listen(Stream<Object?> stream, void Function(Object?) callback) {
    final id = _reference++;
    _listeners[id] = stream.listen(
      callback,
      onError: (Object error) => _errors.add(error),
      onDone: () => _listeners.remove(id),
    );
    return id;
  }

  bool unsubscribe(int id) {
    final subscription = _listeners.remove(id);
    if (subscription == null) return false;
    unawaited(subscription.cancel());
    return true;
  }

  Future<void> close() async {
    final subscriptions = _listeners.values.toList();
    _listeners.clear();
    await Future.wait(subscriptions.map((s) => s.cancel()));
  }

  /// The `message` events from [url], reconnecting until cancelled.
  Stream<ServerSentEvent> subscribe(String url) {
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
          final request = http.Request('GET', Uri.parse(url))
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
            if (event != null && event.type == 'message') {
              controller.add(event);
            }
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
          retry == null ? _retryDelay : Duration(milliseconds: retry),
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
}
