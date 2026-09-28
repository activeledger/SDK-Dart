import 'connection.dart';
import 'crypto/crypto_provider.dart';
import 'events.dart';
import 'key.dart';
import 'key_type.dart';
import 'payload.dart';
import 'transaction.dart';

/// Everything in one place, for the common case.
///
/// ```dart
/// final ledger = Activeledger('http://localhost:5260');
///
/// final key = ledger.keys.generateKey('me', type: KeyType.preferredPostQuantum);
/// await ledger.onboard(key);
///
/// final tx = ledger.transactions.labelledTransaction(
///   key: key, namespace: 'default', contract: 'mycontract',
///   inputLabel: 'input', stream: key.identity!, inputData: {'hello': 'world'},
/// );
/// final response = await ledger.send(tx);
/// ```
///
/// There is deliberately no storage endpoint: a node's storage service
/// listens only on the node's own host. State is read through a transaction
/// - name streams in `$r` and have the contract return values with
/// `returnToRemote`, which arrive in [LedgerResponse.responses].
class Activeledger {
  Activeledger(
    String nodeUrl, {
    String? storageUrl,
    CryptoProvider crypto = const DefaultCryptoProvider(),
  }) : connection = Connection.fromUrl(nodeUrl),
       keys = KeyHandler(crypto: crypto),
       transactions = TransactionHandler(crypto: crypto),
       payloads = PayloadHandler(crypto: crypto),
       storageUrl = storageUrl ?? _defaultStorage(nodeUrl);

  /// The node transactions are sent to.
  final Connection connection;

  final KeyHandler keys;
  final TransactionHandler transactions;
  final PayloadHandler payloads;

  /// The node's storage service, where contract events are served from.
  /// Defaults to the node's host one port below it (5260 -> 5259), which is
  /// how a node lays out its services unless configured otherwise.
  final String storageUrl;

  /// Contract events from the node's database. Created on first use.
  LedgerEvents get events => _events ??= LedgerEvents(storageUrl);
  LedgerEvents? _events;

  static String _defaultStorage(String nodeUrl) {
    final uri = Uri.parse(nodeUrl);
    return uri.replace(port: uri.port - 1, path: '').toString();
  }

  /// Generates a key. Shorthand for [KeyHandler.generateKey].
  Key generateKey(
    String name, {
    KeyType type = KeyType.secp256k1,
    bool compressed = false,
  }) => keys.generateKey(name, type: type, compressed: compressed);

  /// Onboards [key], setting its identity. See [KeyHandler.onboardKey].
  Future<LedgerResponse> onboard(Key key) => keys.onboardKey(key, connection);

  /// Sends a signed transaction.
  Future<LedgerResponse> send(Transaction tx) => connection.sendTransaction(tx);

  /// Releases the HTTP client and any event subscriptions.
  Future<void> close() async {
    connection.close();
    await _events?.close();
  }
}
