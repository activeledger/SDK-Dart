import 'dart:convert';

import 'package:http/http.dart' as http;

import 'canonical.dart';
import 'errors.dart';
import 'transaction.dart';

/// A connection to one Activeledger node.
///
/// ```dart
/// final connection = Connection('http', 'localhost', 5260);
/// // or
/// final connection = Connection.fromUrl('http://localhost:5260');
/// ```
class Connection {
  /// A connection to `protocol://address:port`.
  Connection(
    String protocol,
    String address,
    Object port, {
    http.Client? client,
  }) : this.fromUrl('$protocol://$address:$port', client: client);

  /// A connection to the node at [url].
  Connection.fromUrl(String url, {http.Client? client})
    : baseUri = Uri.parse(url),
      _client = client ?? http.Client(),
      _ownsClient = client == null {
    if (!baseUri.hasScheme ||
        !(baseUri.isScheme('http') || baseUri.isScheme('https'))) {
      throw ArgumentError.value(
        url,
        'url',
        'must start with http:// or https://',
      );
    }
  }

  /// The node's address.
  final Uri baseUri;

  final http.Client _client;
  final bool _ownsClient;

  /// Sends a transaction and returns the ledger's response.
  ///
  /// Accepts a [Transaction] or an already-built envelope map. The body is
  /// serialised with [canonicalJson], so the `$tx` the node receives is
  /// byte-identical to the one that was signed.
  ///
  /// **A rejected transaction is HTTP 200.** Check
  /// [LedgerResponse.committed], never only that this did not throw. This
  /// throws a [LedgerHttpException] for a non-2xx status, and an
  /// [ActiveledgerException] for a 2xx body that is not a JSON object.
  Future<LedgerResponse> sendTransaction(Object transaction) async {
    final body = transaction is Transaction
        ? canonicalJson(transaction.toJson())
        : transaction is String
        ? transaction
        : canonicalJson(transaction);
    final response = await _client.post(
      baseUri,
      headers: {'Content-Type': 'application/json'},
      body: utf8.encode(body),
    );
    final text = utf8.decode(response.bodyBytes, allowMalformed: true);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw LedgerHttpException(response.statusCode, text);
    }
    final Object? decoded;
    try {
      decoded = jsonDecode(text);
    } on FormatException {
      throw ActiveledgerException('Unexpected ledger response: $text');
    }
    if (decoded is! Map) {
      throw ActiveledgerException('Unexpected ledger response: $text');
    }
    return LedgerResponse(decoded.cast<String, Object?>());
  }

  /// Closes the underlying HTTP client, if this connection created it.
  void close() {
    if (_ownsClient) _client.close();
  }
}

/// The ledger's reply to a submitted transaction.
class LedgerResponse {
  LedgerResponse(this.raw);

  /// The decoded JSON, for anything the typed getters do not cover.
  final Map<String, Object?> raw;

  /// The transaction's unique id.
  String? get umid {
    final value = raw[r'$umid'];
    return value is String ? value : null;
  }

  /// Consensus totals.
  LedgerSummary get summary => LedgerSummary(_map(raw[r'$summary']));

  /// Streams created and updated.
  LedgerStreams get streams => LedgerStreams(_map(raw[r'$streams']));

  /// Values a contract returned with `returnToRemote`. This is how state is
  /// read: name the streams in `$r` and have the contract hand values back.
  List<Object?> get responses {
    final value = raw[r'$responses'];
    return value is List ? value.cast<Object?>() : const [];
  }

  /// The echoed transaction, when the node runs in debug mode.
  Object? get debug => raw[r'$debug'];

  /// Errors the network reported. Non-empty means the transaction did NOT
  /// commit, even though the HTTP status was 200. Empty does not mean it
  /// did: see [committed].
  List<String> get errors => summary.errors;

  /// Whether the transaction committed: the reply has a `$summary` object
  /// and its `errors` are absent or empty. A reply with no `$summary` (a
  /// `{}`, say) is not a ledger answer, so it is not committed.
  bool get committed {
    final summary = raw[r'$summary'];
    if (summary is! Map) return false;
    final errors = summary['errors'];
    return errors == null || (errors is List && errors.isEmpty);
  }

  Object? operator [](String key) => raw[key];

  @override
  String toString() => jsonEncode(raw);

  static Map<String, Object?> _map(Object? value) =>
      value is Map ? value.cast<String, Object?>() : const {};
}

/// `$summary`: how many nodes took part, voted and committed.
class LedgerSummary {
  LedgerSummary(this.raw);

  final Map<String, Object?> raw;

  int? get total => _int(raw['total']);
  int? get vote => _int(raw['vote']);
  int? get commit => _int(raw['commit']);

  static int? _int(Object? value) => value is num ? value.toInt() : null;

  List<String> get errors {
    final value = raw['errors'];
    if (value == null) return const [];
    if (value is! List) return [value is String ? value : jsonEncode(value)];
    return [for (final e in value) e is String ? e : jsonEncode(e)];
  }
}

/// `$streams`: stream ids the transaction created and updated.
class LedgerStreams {
  LedgerStreams(this.raw);

  final Map<String, Object?> raw;

  /// Streams created - `$streams.new`. The first one after onboarding is the
  /// new identity.
  List<StreamRef> get created => _refs(raw['new']);

  /// Streams updated - `$streams.updated`.
  List<StreamRef> get updated => _refs(raw['updated']);

  static List<StreamRef> _refs(Object? value) => value is List
      ? [
          for (final item in value)
            if (item is Map && item['id'] is String)
              StreamRef(
                item['id'] as String,
                item['name'] is String ? item['name'] as String : null,
              ),
        ]
      : const [];
}

/// A stream id and its name.
class StreamRef {
  const StreamRef(this.id, this.name);

  final String id;
  final String? name;

  @override
  String toString() => name == null ? id : '$id ($name)';
}
