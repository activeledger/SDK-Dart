import 'canonical.dart';
import 'crypto/crypto_provider.dart';
import 'key.dart';
import 'key_type.dart';

/// Signs and verifies arbitrary payloads - an exchange order, an
/// attestation, an auth challenge - as opposed to transactions, which
/// [TransactionHandler] covers.
class PayloadHandler {
  PayloadHandler({CryptoProvider crypto = const DefaultCryptoProvider()})
    : _crypto = crypto;

  final CryptoProvider _crypto;

  /// The exact string [sign] and [verify] operate on.
  ///
  /// Worth using. An object is canonicalised with [canonicalJson], which is
  /// **key-order sensitive**: the same fields in a different insertion order
  /// produce different bytes and so a signature that will not verify.
  ///
  /// ```text
  /// {"pair":"VNR/USDT","side":"sell"}   and
  /// {"side":"sell","pair":"VNR/USDT"}   do not match
  /// ```
  ///
  /// That is safe while a payload round-trips as JSON, because key order
  /// survives. It stops being safe the moment anything rebuilds the object
  /// field by field before verifying. So persist what this returns alongside
  /// the signature, and verify THAT.
  String canonical(Object? payload) =>
      payload is String ? payload : canonicalJson(payload);

  /// Signs [payload] (an object, or a string from [canonical]) with [key],
  /// returning a base64 signature. The key carries its own scheme.
  String sign(Object? payload, Key key) =>
      _crypto.sign(canonical(payload), key.key.privateKey, type: key.type);

  /// Verifies [payload] against a signer's [publicKey] and [type] - usually
  /// taken off the ledger, since whoever verifies is rarely whoever signed.
  ///
  /// Returns false rather than throwing on malformed input: a wrong
  /// signature and an unparseable one mean the same thing to a caller.
  bool verify(
    Object? payload,
    String signature,
    String publicKey, {
    KeyType type = KeyType.secp256k1,
  }) {
    try {
      return _crypto.verify(
        canonical(payload),
        signature,
        publicKey,
        type: type,
      );
    } catch (_) {
      return false;
    }
  }
}
