import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'connection.dart';
import 'crypto/crypto_provider.dart';
import 'errors.dart';
import 'key_type.dart';
import 'recovery.dart';
import 'transaction.dart';

/// The encoded halves of a key pair, as the ledger and key files carry them.
///
/// secp256k1 keys are `0x`-prefixed hex, post-quantum keys are base64 of the
/// raw bytes, and legacy RSA keys are PEM.
///
/// Serialises to the JavaScript SDK's shape - `{"pub":{"pkcs8pem":...},
/// "prv":{"pkcs8pem":...}}` - so key files move between the two unchanged.
/// The field is called `pkcs8pem` there for historical reasons; it is not
/// PEM for anything but RSA.
class KeyMaterial {
  const KeyMaterial({required this.publicKey, required this.privateKey});

  factory KeyMaterial.fromJson(Map<String, Object?> json) {
    String read(String half) {
      final details = json[half];
      if (details is Map && details['pkcs8pem'] is String) {
        return details['pkcs8pem'] as String;
      }
      throw FormatException('Key file is missing $half.pkcs8pem');
    }

    return KeyMaterial(publicKey: read('pub'), privateKey: read('prv'));
  }

  /// Give this to the ledger.
  final String publicKey;

  /// Keep this.
  final String privateKey;

  Map<String, Object?> toJson() => {
    'prv': {'pkcs8pem': privateKey},
    'pub': {'pkcs8pem': publicKey},
  };
}

/// A named key, and the identity (stream id) it controls once onboarded.
///
/// The Dart counterpart of the JavaScript SDK's `IKey`, and serialised the
/// same way, so a key exported by either SDK imports into the other.
class Key {
  Key({
    required this.name,
    required this.type,
    required this.key,
    this.identity,
    this.phrase,
  });

  factory Key.fromJson(Map<String, Object?> json) {
    final name = json['name'];
    final type = json['type'];
    final key = json['key'];
    if (name is! String) throw const FormatException('Key file has no name');
    if (type is! String) {
      // The ledger defaults a missing type to rsa, which is never what a
      // modern key is, so a guess here would be wrong in the worst way.
      throw const FormatException('Key file has no type');
    }
    if (key is! Map) throw const FormatException('Key file has no key');
    return Key(
      name: name,
      type: KeyType.fromWire(type),
      key: KeyMaterial.fromJson(key.cast<String, Object?>()),
      identity: json['identity'] as String?,
      phrase: json['phrase'] as String?,
    );
  }

  /// The name the key is known by - the `$i` label when onboarding.
  final String name;

  /// The signature scheme.
  final KeyType type;

  /// The encoded key pair.
  final KeyMaterial key;

  /// The identity stream id, set once the key has been onboarded.
  String? identity;

  /// The BIP-39 recovery phrase, when the key was made from one.
  final String? phrase;

  /// The public key, as given to the ledger.
  String get publicKey => key.publicKey;

  Map<String, Object?> toJson() => {
    'key': key.toJson(),
    'name': name,
    'type': type.wire,
    'phrase': ?phrase,
    'identity': ?identity,
  };

  @override
  String toString() =>
      'Key($name, ${type.wire}${identity == null ? '' : ', $identity'})';
}

/// Generates, recovers, onboards and stores keys.
class KeyHandler {
  KeyHandler({CryptoProvider crypto = const DefaultCryptoProvider()})
    : _crypto = crypto;

  final CryptoProvider _crypto;

  /// A new key.
  ///
  /// [compressed] selects a 33-byte rather than 65-byte secp256k1 public key
  /// (the ledger accepts both) and is ignored by the post-quantum schemes.
  /// For a post-quantum identity with the smallest signatures available,
  /// pass `type: KeyType.preferredPostQuantum`.
  Key generateKey(
    String name, {
    KeyType type = KeyType.secp256k1,
    bool compressed = false,
  }) => Key(
    name: name,
    type: type,
    key: _crypto.generate(type: type, compressed: compressed),
  );

  /// Recreates a key from the algorithm's own seed.
  ///
  /// No KDF is applied: the bytes given are the seed the scheme itself takes
  /// - 32 for secp256k1 and ml-dsa-65, 48 for falcon-512. The same seed
  /// produces the same identity in every Activeledger SDK, which makes a
  /// seed the one private-key format all of them can exchange.
  Key generateKeyFromSeed(
    String name,
    Uint8List seed, {
    KeyType type = KeyType.secp256k1,
    bool compressed = false,
  }) => Key(
    name: name,
    type: type,
    key: _crypto.generateFromSeed(seed, type: type, compressed: compressed),
  );

  /// A new key with a fresh 12-word BIP-39 recovery phrase, available as
  /// [Key.phrase]. Options are as for [restoreBip39Key].
  Key generateBip39Key(
    String name, {
    KeyType type = KeyType.secp256k1,
    String passphrase = '',
    bool compressed = false,
  }) => restoreBip39Key(
    name,
    Recovery.generateMnemonic(),
    type: type,
    passphrase: passphrase,
    compressed: compressed,
  );

  /// Recreates a key from a BIP-39 recovery phrase.
  ///
  /// Each [type] derives its own seed from the phrase (see [Recovery]), so
  /// one phrase can back a secp256k1, an ml-dsa-65 and a falcon-512
  /// identity at once without any of them revealing the others.
  ///
  /// The phrase is validated - wordlist and checksum - unless [validate] is
  /// false, because an unchecked typo derives a different VALID key for an
  /// identity nobody owns.
  ///
  /// [legacy] reproduces the original `@activeledger/sdk-bip39` scheme,
  /// SHA256(phrase) used directly as a secp256k1 key. Use it only to recover
  /// a phrase made by that package; never for new keys. It ignores
  /// [passphrase] and [validate].
  Key restoreBip39Key(
    String name,
    String phrase, {
    KeyType type = KeyType.secp256k1,
    String passphrase = '',
    bool compressed = false,
    bool legacy = false,
    bool validate = true,
  }) {
    if (legacy && type != KeyType.secp256k1) {
      // Silently ignoring it for a post-quantum type would hand back a key
      // from the modern derivation while the caller believed they were
      // recovering an old one.
      throw ArgumentError(
        'The legacy BIP-39 scheme is secp256k1 only - it '
        'cannot derive ${type.wire}',
      );
    }
    final seed = legacy
        ? Recovery.legacySeed(phrase)
        : Recovery.deriveSeed(
            type,
            Recovery.toSeed(phrase, passphrase: passphrase, validate: validate),
          );
    return Key(
      name: name,
      type: type,
      key: _crypto.generateFromSeed(seed, type: type, compressed: compressed),
      phrase: phrase,
    );
  }

  /// Onboards [key] - creating its identity on the ledger - and sets
  /// [Key.identity] to the new stream id.
  ///
  /// Throws an [OnboardException] if the ledger did not create a stream,
  /// rather than returning a response whose identity is missing: an
  /// onboarding that silently produced nothing surfaces three calls later.
  Future<LedgerResponse> onboardKey(
    Key key,
    Connection connection, {
    String contract = 'onboard',
    String namespace = 'default',
  }) async {
    final handler = TransactionHandler(crypto: _crypto);
    final tx = handler.buildOnboardKeyTx(
      key,
      contract: contract,
      namespace: namespace,
    );
    final response = await handler.sendTransaction(tx, connection);
    final created = response.streams.created;
    if (created.isEmpty) {
      throw OnboardException(
        'Onboarding "${key.name}" created no identity'
        '${response.errors.isEmpty ? '' : ': ${response.errors.join('; ')}'}',
        response.raw,
      );
    }
    key.identity = created.first.id;
    return response;
  }

  /// Writes [key] to `<location>/<name ?? key.name>.json` in the JavaScript
  /// SDK's key file format.
  ///
  /// The file contains the private key. Store it accordingly.
  Future<void> exportKey(
    Key key,
    String location, {
    bool createDir = false,
    bool overwrite = false,
    String? name,
  }) async {
    final dir = Directory(location);
    if (createDir) await dir.create(recursive: true);
    if (!await dir.exists()) {
      throw FileSystemException('Unable to find location', location);
    }
    final base = location.endsWith('/')
        ? location.substring(0, location.length - 1)
        : location;
    final file = File('$base/${name ?? key.name}.json');
    if (await file.exists() && !overwrite) {
      throw FileSystemException(
        'File already exists, set overwrite to true or use a different name',
        file.path,
      );
    }
    await file.writeAsString(jsonEncode(key.toJson()));
  }

  /// Reads a key file written by [exportKey] or by the JavaScript SDK.
  Future<Key> importKey(String path) async {
    final file = File(path);
    if (!await file.exists()) {
      throw FileSystemException('File not found', path);
    }
    final json = jsonDecode(await file.readAsString());
    if (json is! Map) throw FormatException('Not a key file', path);
    return Key.fromJson(json.cast<String, Object?>());
  }
}
