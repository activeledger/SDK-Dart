import 'package:activeledger_falcon/activeledger_falcon.dart';

Future<void> main() async {
  // One call at startup. Returns false (and leaves the SDK on ML-DSA-65)
  // if the native library cannot be loaded.
  if (!ActiveledgerFalcon.enable()) {
    print('Falcon unavailable: ${ActiveledgerFalcon.failure}');
  }

  final ledger = Activeledger('http://localhost:5260');
  final key = ledger.generateKey(
    'identity',
    type: KeyType.preferredPostQuantum,
  );
  print('Generated a ${key.type} key');

  await ledger.onboard(key);
  print('Onboarded ${key.identity}');
  await ledger.close();
}
