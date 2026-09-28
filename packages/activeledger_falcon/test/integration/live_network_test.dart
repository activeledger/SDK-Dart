// Falcon-512 against a real Activeledger network. See the activeledger
// package's live test for how to start one; skips when AL_NODES is unset.
@TestOn('vm')
library;

import 'dart:io';

import 'package:activeledger_falcon/activeledger_falcon.dart';
import 'package:test/test.dart';

String _unique(String prefix) =>
    '$prefix${DateTime.now().microsecondsSinceEpoch % 100000000}';

void main() {
  final nodes = Platform.environment['AL_NODES'];
  if (nodes == null) {
    test(
      'live network',
      () {},
      skip:
          'AL_NODES not set - start `npm run test:network:serve` in the '
          'activeledger repo',
    );
    return;
  }

  setUpAll(() => ActiveledgerFalcon.enable(throwOnFailure: true));
  final ledger = Activeledger(nodes.split(',').first);
  tearDownAll(ledger.close);

  Transaction namespaceTx(Key key, String prefix) => Transaction(
    tx: {
      r'$namespace': 'default',
      r'$contract': 'namespace',
      r'$i': {
        key.identity!: {'namespace': _unique(prefix)},
      },
    },
  );

  test('a generated falcon-512 identity onboards and transacts', () async {
    final key = ledger.generateKey('identity', type: KeyType.falcon512);
    expect((await ledger.onboard(key)).committed, isTrue);

    final tx = ledger.transactions.signTransaction(
      namespaceTx(key, 'dartf'),
      key,
    );
    final response = await ledger.send(tx);
    expect(response.committed, isTrue, reason: '$response');
  });

  test('a seed-derived falcon-512 identity onboards and transacts', () async {
    final phrase = Recovery.generateMnemonic();
    final key = ledger.keys.restoreBip39Key(
      'identity',
      phrase,
      type: KeyType.falcon512,
    );
    expect((await ledger.onboard(key)).committed, isTrue);

    final recovered = ledger.keys.restoreBip39Key(
      'identity',
      phrase,
      type: KeyType.falcon512,
    )..identity = key.identity;
    final tx = ledger.transactions.signTransaction(
      namespaceTx(recovered, 'dartfs'),
      recovered,
    );
    expect((await ledger.send(tx)).committed, isTrue);
  });

  test('a tampered falcon-512 payload is rejected', () async {
    final key = ledger.generateKey('identity', type: KeyType.falcon512);
    await ledger.onboard(key);
    final honest = ledger.transactions.signTransaction(
      namespaceTx(key, 'dartft'),
      key,
    );
    final tampered = honest.toString().replaceFirst('dartft', 'dartfx');
    final response = await ledger.connection.sendTransaction(tampered);
    expect(response.committed, isFalse, reason: '$response');
  });
}
