// Runs against a real Activeledger network.
//
// Everything else here checks the SDK against published vectors. This checks
// it against running nodes, which are the only thing that actually decides
// whether a signature is acceptable: the type string, the $sigs keying and
// the exact signed bytes are all invisible to a unit test.
//
// Start the 4-node network from an activeledger checkout:
//
//   npm run test:network:serve
//
// then, with the URLs it prints:
//
//   AL_NODES=http://localhost:5510 AL_STORAGE=http://localhost:5509 \
//     dart test test/integration
//
// Skips when AL_NODES is unset, so `dart test` works with no ledger.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:activeledger/activeledger.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

final String? _nodes = Platform.environment['AL_NODES'];
final String? _storage = Platform.environment['AL_STORAGE'];

String _unique(String prefix) =>
    '$prefix${DateTime.now().microsecondsSinceEpoch % 100000000}';

/// Reads a document from a node's storage service - only reachable because
/// this is a local test network, which is why it is here and not in the SDK.
Future<Map<String, Object?>?> _authority(String streamId) async {
  final storage = _storage?.split(',').first;
  if (storage == null) return null;
  final deadline = DateTime.now().add(const Duration(seconds: 15));
  while (DateTime.now().isBefore(deadline)) {
    final response = await http.get(
      Uri.parse(
        '$storage/activeledger/${Uri.encodeComponent('$streamId:stream')}',
      ),
    );
    if (response.statusCode == 200) {
      final doc = jsonDecode(response.body);
      final authorities = doc is Map ? doc['authorities'] : null;
      if (authorities is List && authorities.isNotEmpty) {
        return (authorities.first as Map).cast<String, Object?>();
      }
    }
    await Future<void>.delayed(const Duration(milliseconds: 500));
  }
  fail('identity meta for $streamId never appeared in storage');
}

void main() {
  final nodes = _nodes;
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

  final ledger = Activeledger(nodes.split(',').first);
  tearDownAll(ledger.close);

  final cases = <(String, KeyType, bool)>[
    ('secp256k1 compressed', KeyType.secp256k1, true),
    ('secp256k1 uncompressed', KeyType.secp256k1, false),
    ('ml-dsa-65', KeyType.mlDsa65, false),
    if (PostQuantum.isAvailable(KeyType.falcon512))
      ('falcon-512', KeyType.falcon512, false),
  ];

  for (final (name, type, compressed) in cases) {
    group(name, () {
      late Key key;

      test('onboards, and the ledger records the key exactly', () async {
        key = ledger.keys.generateKey(
          'identity',
          type: type,
          compressed: compressed,
        );
        final response = await ledger.onboard(key);
        expect(response.committed, isTrue, reason: '$response');
        expect(key.identity, isNotEmpty);

        final authority = await _authority(key.identity!);
        if (authority != null) {
          expect(authority['type'], type.wire);
          expect(authority['public'], key.publicKey);
        }
      });

      test('a stream-keyed transaction is accepted', () async {
        final tx = Transaction(
          tx: {
            r'$namespace': 'default',
            r'$contract': 'namespace',
            r'$i': {
              key.identity!: {'namespace': _unique('dart')},
            },
          },
        );
        ledger.transactions.signTransaction(tx, key);
        final response = await ledger.send(tx);
        expect(response.committed, isTrue, reason: '$response');
      });

      test('a labelled transaction is accepted', () async {
        final tx = ledger.transactions.labelledTransaction(
          key: key,
          namespace: 'default',
          contract: 'namespace',
          inputLabel: key.identity!,
          stream: key.identity!,
          inputData: {'namespace': _unique('dartl')},
        );
        final response = await ledger.send(tx);
        expect(response.committed, isTrue, reason: '$response');
      });

      test('a tampered payload is rejected', () async {
        final honest = Transaction(
          tx: {
            r'$namespace': 'default',
            r'$contract': 'namespace',
            r'$i': {
              key.identity!: {'namespace': _unique('dartt')},
            },
          },
        );
        ledger.transactions.signTransaction(honest, key);
        // Same signature, different body - sent raw, because signing again
        // would produce a valid transaction.
        final tampered = honest.toString().replaceFirst('dartt', 'dartx');
        final response = await ledger.connection.sendTransaction(tampered);
        expect(response.committed, isFalse, reason: '$response');
      });
    });
  }

  test('a recovered key signs for the identity it onboarded', () async {
    final phrase = Recovery.generateMnemonic();
    final original = ledger.keys.restoreBip39Key(
      'identity',
      phrase,
      type: KeyType.mlDsa65,
    );
    await ledger.onboard(original);

    final recovered = ledger.keys.restoreBip39Key(
      'identity',
      phrase,
      type: KeyType.mlDsa65,
    )..identity = original.identity;
    final tx = Transaction(
      tx: {
        r'$namespace': 'default',
        r'$contract': 'namespace',
        r'$i': {
          recovered.identity!: {'namespace': _unique('dartr')},
        },
      },
    );
    ledger.transactions.signTransaction(tx, recovered);
    expect((await ledger.send(tx)).committed, isTrue);
  });
}
