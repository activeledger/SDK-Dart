import 'package:activeledger/activeledger.dart';

/// Onboards an identity and submits a transaction.
///
/// Run a node locally first (default port 5260), then:
///
///     dart run example/example.dart
Future<void> main() async {
  final ledger = Activeledger('http://localhost:5260');

  // secp256k1 is the smallest; KeyType.preferredPostQuantum gives
  // Falcon-512 when the add-on is enabled and ML-DSA-65 otherwise.
  final key = ledger.generateKey(
    'identity',
    type: KeyType.preferredPostQuantum,
  );

  final onboard = await ledger.onboard(key);
  print('Onboarded ${key.identity} (committed: ${onboard.committed})');

  final tx = ledger.transactions.labelledTransaction(
    key: key,
    namespace: 'default',
    contract: 'namespace',
    inputLabel: key.identity!,
    stream: key.identity!,
    inputData: {'namespace': 'example${DateTime.now().millisecondsSinceEpoch}'},
  );

  final response = await ledger.send(tx);
  if (!response.committed) {
    // A rejected transaction is still HTTP 200.
    print('Rejected: ${response.errors}');
  } else {
    print('Committed ${response.umid}');
  }

  await ledger.close();
}
