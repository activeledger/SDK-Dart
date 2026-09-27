import 'crypto/post_quantum.dart';

/// The key types Activeledger understands, and their exact wire strings.
///
/// **These strings are the whole contract.** The ledger validates nothing
/// else about them: the value travels from `$tx.$i[label].type` into the
/// identity stream's `meta.authorities[].type` verbatim, and comes back out
/// at verification time. Two consequences worth knowing before debugging
/// anything:
///
/// - A typo in the string, or a key of the wrong length, surfaces as **1220
///   "Signature Incorrect"**, never as "unknown algorithm".
/// - **The ledger defaults a missing type to `rsa`.** Omitting it for a
///   post-quantum key produces an RSA verification attempt against a base64
///   blob, so this SDK always sends it explicitly.
enum KeyType {
  /// secp256k1 ECDSA. Keys are `0x`-prefixed hex; signatures are SHA-256,
  /// then ECDSA, then DER.
  secp256k1('secp256k1'),

  /// ML-DSA-65 (FIPS 204). The conservative post-quantum choice - a finalised
  /// standard, at the cost of 1952 byte public keys and 3309 byte signatures
  /// against secp256k1's 33 and ~71. Always available: implemented in pure
  /// Dart.
  mlDsa65('ml-dsa-65'),

  /// Falcon-512 (FN-DSA). Roughly a fifth of ML-DSA-65's signature size,
  /// which matters because every signature is broadcast to every node and
  /// stored for the life of the ledger.
  ///
  /// Its signature length VARIES, 649-662 bytes, because the encoding
  /// compresses. Do not assume a fixed width anywhere.
  ///
  /// Needs the `activeledger_falcon` package - see
  /// [PostQuantum.isAvailable].
  falcon512('falcon-512'),

  /// RSA, for legacy identities only (for example a network's contract
  /// deployer). Existing PEM keys can sign and verify; new ones cannot be
  /// generated.
  rsa('rsa');

  const KeyType(this.wire);

  /// The exact string the ledger stores and compares.
  final String wire;

  /// True for the post-quantum schemes, whose keys are base64 raw bytes.
  bool get isPostQuantum => this == mlDsa65 || this == falcon512;

  /// The post-quantum members of [KeyType].
  static const List<KeyType> postQuantum = [mlDsa65, falcon512];

  /// The best post-quantum scheme available in this process.
  ///
  /// Falcon-512 when the `activeledger_falcon` add-on has been enabled,
  /// otherwise ML-DSA-65, which is always available. Use this when you want
  /// a post-quantum identity and prefer the smaller signatures when you can
  /// get them.
  static KeyType get preferredPostQuantum =>
      PostQuantum.isAvailable(falcon512) ? falcon512 : mlDsa65;

  /// Parses a wire string, throwing on anything unrecognised.
  ///
  /// Deliberately strict and case-sensitive: the ledger compares these
  /// exactly, so accepting `ML-DSA-65` here would only move the failure
  /// somewhere less informative. `bitcoin` and `ethereum` parse as
  /// [secp256k1], because the ledger routes them to identical verification;
  /// they are never emitted.
  static KeyType fromWire(String value) {
    for (final type in values) {
      if (type.wire == value) return type;
    }
    if (value == 'bitcoin' || value == 'ethereum') return secp256k1;
    throw ArgumentError.value(
      value,
      'type',
      'Unknown key type - expected one of '
          '${values.map((t) => t.wire).join(', ')}',
    );
  }

  @override
  String toString() => wire;
}
