// Smoke test: builds a throwaway consumer package outside the repo that
// depends on packages/activeledger by path, then pub-gets, analyzes and runs
// it. The consumer generates secp256k1 and ml-dsa-65 keys, builds, signs and
// verifies a transaction, and submits it to a loopback HttpServer that
// answers once with a committed reply and once with a rejected HTTP 200
// reply. No external network.
//
//   dart scripts/smoke.dart
import 'dart:io';

const _main = r'''
import 'dart:convert';
import 'dart:io';

import 'package:activeledger/activeledger.dart';

void check(bool ok, String what) {
  if (!ok) {
    stderr.writeln('SMOKE FAILED: $what');
    exit(1);
  }
}

Future<void> main() async {
  final received = <String>[];
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((request) async {
    final body = await utf8.decoder.bind(request).join();
    received.add(body);
    final committed = received.length.isOdd;
    request.response.write(
      jsonEncode({
        r'$umid': 'umid-${received.length}',
        r'$summary': committed
            ? {'total': 1, 'vote': 1, 'commit': 1}
            : {
                'total': 1,
                'vote': 0,
                'commit': 0,
                'errors': ['Signature Incorrect'],
              },
        r'$streams': {'new': <Object?>[]},
      }),
    );
    await request.response.close();
  });

  final ledger = Activeledger('http://127.0.0.1:${server.port}');
  const crypto = DefaultCryptoProvider();

  for (final type in [KeyType.secp256k1, KeyType.mlDsa65]) {
    final key = ledger.generateKey('smoke-${type.wire}', type: type);
    key.identity = 'stream-${type.wire}';
    final tx = ledger.transactions.labelledTransaction(
      key: key,
      namespace: 'default',
      contract: 'smoke',
      inputLabel: 'in',
      stream: key.identity!,
      inputData: {'type': type.wire},
    );

    final signature = tx.sigs[key.identity!]!;
    check(
      crypto.verify(tx.signedString, signature, key.key.publicKey, type: type),
      '${type.wire} signature verifies',
    );
    check(
      !crypto.verify(
        '${tx.signedString} ',
        signature,
        key.key.publicKey,
        type: type,
      ),
      '${type.wire} signature rejects a changed message',
    );

    final before = received.length;
    final committed = await ledger.send(tx);
    check(committed.committed, '${type.wire} committed reply');
    final rejected = await ledger.send(tx);
    check(!rejected.committed, '${type.wire} rejected HTTP 200 reply');
    check(
      rejected.errors.single == 'Signature Incorrect',
      '${type.wire} rejection reason',
    );
    check(received.length == before + 2, '${type.wire} two requests seen');
    check(received[before] == canonicalJson(tx.toJson()), 'body is the envelope');
    stdout.writeln('ok ${type.wire}');
  }

  await ledger.close();
  await server.close(force: true);
  stdout.writeln('SMOKE OK');
}
''';

Future<void> _run(
  String what,
  List<String> args,
  String dir, {
  bool echo = false,
}) async {
  final result = await Process.run(
    Platform.resolvedExecutable,
    args,
    workingDirectory: dir,
    runInShell: Platform.isWindows,
  );
  if (echo) stdout.write(result.stdout);
  if (result.exitCode != 0) {
    stderr
      ..writeln('SMOKE FAILED at "$what" (exit ${result.exitCode})')
      ..write(result.stdout)
      ..write(result.stderr);
    exit(1);
  }
}

Future<void> main() async {
  final repo = File.fromUri(Platform.script).parent.parent.path;
  final package =
      '$repo${Platform.pathSeparator}packages'
      '${Platform.pathSeparator}activeledger';
  if (!Directory(package).existsSync()) {
    stderr.writeln('Cannot find $package');
    exit(1);
  }

  final dir = Directory.systemTemp.createTempSync('activeledger_smoke_');
  try {
    // Forward slashes keep the path valid YAML on Windows.
    final path = package.replaceAll(r'\', '/');
    File('${dir.path}/pubspec.yaml').writeAsStringSync('''
name: smoke_consumer
publish_to: none
environment:
  sdk: ^3.10.0
dependencies:
  activeledger:
    path: $path
''');
    Directory('${dir.path}/bin').createSync();
    File('${dir.path}/bin/main.dart').writeAsStringSync(_main);

    await _run('dart pub get --offline', ['pub', 'get', '--offline'], dir.path);
    await _run('dart analyze', ['analyze', '--fatal-infos'], dir.path);
    await _run('dart run', ['run', 'bin/main.dart'], dir.path, echo: true);
  } finally {
    dir.deleteSync(recursive: true);
  }
}
