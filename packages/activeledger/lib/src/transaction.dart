import 'canonical.dart';
import 'connection.dart';
import 'crypto/crypto_provider.dart';
import 'key.dart';

/// A transaction envelope: the `$tx` body, its `$sigs`, and `$selfsign`.
///
/// Signatures cover [canonicalJson] of [tx] and nothing else - not the
/// envelope, not a hash of it, not a length-prefixed form.
///
/// [tx] is an ordinary map, and its insertion order is what gets signed,
/// because the ledger does not sort keys. Build it once and sign it; if you
/// edit it after signing, sign it again.
class Transaction {
  Transaction({required this.tx, Map<String, String>? sigs, this.selfsign})
    : sigs = sigs ?? {};

  factory Transaction.fromJson(Map<String, Object?> json) {
    final tx = json[r'$tx'];
    if (tx is! Map) throw const FormatException(r'Transaction has no $tx');
    final sigs = json[r'$sigs'];
    return Transaction(
      tx: tx.cast<String, Object?>(),
      sigs: sigs is Map ? sigs.cast<String, String>() : null,
      selfsign: json[r'$selfsign'] as bool?,
    );
  }

  /// The `$tx` body.
  final Map<String, Object?> tx;

  /// Signatures, keyed by signer: the identity stream id normally, or the
  /// `$i` label for a self-signed transaction.
  final Map<String, String> sigs;

  /// Whether this is a self-signed transaction.
  bool? selfsign;

  /// The exact string that is signed. Comparing it against what another
  /// implementation signed is the fastest way to diagnose a 1220
  /// "Signature Incorrect".
  String get signedString => canonicalJson(tx);

  Map<String, Object?> toJson() => {
    r'$selfsign': ?selfsign,
    r'$sigs': sigs,
    r'$tx': tx,
  };

  @override
  String toString() => canonicalJson(toJson());
}

/// Builds, signs and sends transactions.
class TransactionHandler {
  TransactionHandler({CryptoProvider crypto = const DefaultCryptoProvider()})
    : _crypto = crypto;

  final CryptoProvider _crypto;

  /// The onboarding transaction for [key], self-signed.
  ///
  /// Two things here are the most common first failure in a port, so they
  /// are done in one place:
  ///
  /// - `$selfsign` is true, and `$sigs` is keyed by the `$i` label (the key
  ///   name), not by a stream id. There is no stream yet.
  /// - `type` is always present. The ledger defaults a missing type to
  ///   `rsa` and then attempts RSA verification against the key.
  Transaction buildOnboardKeyTx(
    Key key, {
    String contract = 'onboard',
    String namespace = 'default',
  }) {
    final tx = Transaction(
      selfsign: true,
      tx: {
        r'$contract': contract,
        r'$i': {
          key.name: {'publicKey': key.key.publicKey, 'type': key.type.wire},
        },
        r'$namespace': namespace,
      },
    );
    // Keyed by label explicitly, so a key that already has an identity
    // (onboarded elsewhere) still signs under the label the ledger expects.
    return signTransaction(tx, key, selfSignLabel: key.name);
  }

  /// A transaction with one labelled input, signed by [key].
  ///
  /// [key] must already be onboarded (have an [Key.identity]). [inputData]
  /// becomes `$tx.$i[inputLabel]`, with `$stream` set to [stream].
  ///
  /// With [selfsign], the input also carries the key's `publicKey` and
  /// `type`, and `$sigs` is keyed by [inputLabel] rather than the identity -
  /// the ledger's self-signed path looks signatures up by `$i` label.
  Transaction labelledTransaction({
    required Key key,
    required String namespace,
    required String contract,
    required String inputLabel,
    required String stream,
    Map<String, Object?> inputData = const {},
    String? entry,
    Map<String, Object?>? outputs,
    Map<String, Object?>? readonly,
    bool selfsign = false,
  }) {
    if (key.identity == null) {
      throw StateError('Key must have an identity - onboard it first.');
    }

    final input = <String, Object?>{...inputData, r'$stream': stream};
    if (selfsign) {
      input['publicKey'] = key.key.publicKey;
      input['type'] = key.type.wire;
    }

    final body = <String, Object?>{
      r'$contract': contract,
      r'$i': {inputLabel: input},
      r'$namespace': namespace,
      r'$entry': ?entry,
      r'$o': ?outputs,
      r'$r': ?readonly,
    };

    final tx = Transaction(tx: body, selfsign: selfsign ? true : null);
    return signTransaction(
      tx,
      key,
      selfSignLabel: selfsign ? inputLabel : null,
    );
  }

  /// Signs [tx] with [key] and adds the signature to `$sigs`, returning
  /// [tx].
  ///
  /// The signature is keyed by [selfSignLabel] if given, otherwise the key's
  /// identity, otherwise its name. Call it once per signer for a
  /// multi-signature transaction.
  Transaction signTransaction(
    Transaction tx,
    Key key, {
    String? selfSignLabel,
  }) {
    final identifier = selfSignLabel ?? key.identity ?? key.name;
    tx.sigs[identifier] = _crypto.sign(
      canonicalJson(tx.tx),
      key.key.privateKey,
      type: key.type,
    );
    return tx;
  }

  /// Signs an arbitrary string with [key], returning the base64 signature.
  String signString(String data, Key key) =>
      _crypto.sign(data, key.key.privateKey, type: key.type);

  /// Sends [tx] over [connection].
  Future<LedgerResponse> sendTransaction(
    Transaction tx,
    Connection connection,
  ) => connection.sendTransaction(tx);
}
