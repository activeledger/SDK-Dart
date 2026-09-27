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
  /// throws a [LedgerHttpException] only for a non-2xx status.
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
    final decoded = jsonDecode(text);
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
  String? get umid => raw[r'$umid'] as String?;

  /// Consensus totals.
  LedgerSummary get summary => LedgerSummary(_map(raw[r'$summary']));

  /// Streams created and updated.
  LedgerStreams get streams => LedgerStreams(_map(raw[r'$streams']));

  /// Values a contract returned with `returnToRemote`. This is how state is
  /// read: name the streams in `$r` and have the contract hand values back.
  List<Object?> get responses =>
      (raw[r'$responses'] as List<Object?>?) ?? const [];

  /// The echoed transaction, when the node runs in debug mode.
  Object? get debug => raw[r'$debug'];

  /// Errors the network reported. Non-empty means the transaction did NOT
  /// commit, even though the HTTP status was 200.
  List<String> get errors => summary.errors;

  /// Whether the transaction committed.
  bool get committed =>
      errors.isEmpty && (summary.commit == null || summary.commit! > 0);

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

  int? get total => (raw['total'] as num?)?.toInt();
  int? get vote => (raw['vote'] as num?)?.toInt();
  int? get commit => (raw['commit'] as num?)?.toInt();

  List<String> get errors {
    final value = raw['errors'];
    if (value is! List) return const [];
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
            if (item is Map)
              StreamRef(item['id'] as String, item['name'] as String?),
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
