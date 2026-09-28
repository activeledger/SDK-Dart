import 'dart:ffi';
import 'dart:typed_data';

import 'package:activeledger/activeledger.dart';
import 'package:ffi/ffi.dart';
import 'package:liboqs/liboqs.dart';
// The RNG hooks are not re-exported by package:liboqs, and seeded key
// generation needs them - see Falcon512Scheme.fromSeed.
// ignore: implementation_imports
import 'package:liboqs/src/bindings/liboqs_bindings.dart' as oqs;

/// Falcon-512 (FN-DSA), backed by liboqs.
///
/// Byte forms are the ledger's: keys INCLUDE their 1-byte header (0x09
/// public, 0x59 private), so they are 897 and 1281 bytes, and signatures
/// are the compressed, variable-length form (649-662 bytes, header 0x39) -
/// liboqs's `Falcon-512`, NOT `Falcon-padded-512`.
///
/// Signing is randomised, as in the reference SDK: two signatures over one
/// message differ, and both verify.
final class Falcon512Scheme implements PostQuantumScheme {
  Falcon512Scheme() : _sig = Signature.create(algorithm);

  /// The liboqs algorithm name. Not `Falcon-padded-512`, which produces
  /// fixed-length signatures the ledger does not expect.
  static const String algorithm = 'Falcon-512';

  static const int publicHeader = 0x09;
  static const int privateHeader = 0x59;
  static const int signatureHeader = 0x39;

  final Signature _sig;

  @override
  KeyType get type => KeyType.falcon512;

  @override
  int get publicKeyBytes => 897;

  @override
  int get privateKeyBytes => 1281;

  @override
  int get seedBytes => 48;

  @override
  ({Uint8List publicKey, Uint8List privateKey}) generate() {
    final pair = _sig.generateKeyPair();
    return _checked(pair.publicKey, pair.secretKey);
  }

  /// The key pair determined by a 48-byte seed.
  ///
  /// Falcon's key generation reads exactly 48 random bytes and expands them
  /// with SHAKE-256, so feeding it the seed as its randomness gives the key
  /// `@noble/post-quantum` and BouncyCastle derive from the same seed -
  /// checked against the cross-language seed vectors.
  ///
  /// liboqs has no seeded signature keygen, so this points liboqs's RNG at
  /// the seed for the duration of the call and restores the system RNG
  /// afterwards. That RNG is process-wide: do not run other liboqs
  /// operations on other isolates while this runs.
  @override
  ({Uint8List publicKey, Uint8List privateKey}) fromSeed(Uint8List seed) {
    if (seed.length != seedBytes) {
      throw ArgumentError(
        'falcon-512 needs a $seedBytes-byte seed, got ${seed.length}',
      );
    }

    _SeededRandom.begin(seed);
    final callback =
        NativeCallable<Void Function(Pointer<Uint8>, Size)>.isolateLocal(
          _SeededRandom.fill,
        );
    SignatureKeyPair pair;
    try {
      oqs.OQS_randombytes_custom_algorithm(callback.nativeFunction);
      pair = _sig.generateKeyPair();
    } finally {
      final system = 'system'.toNativeUtf8();
      try {
        oqs.OQS_randombytes_switch_algorithm(system.cast());
      } finally {
        calloc.free(system);
        callback.close();
      }
    }

    final consumed = _SeededRandom.end();
    if (consumed != seedBytes) {
      // Anything but exactly the seed means the key is not the portable one
      // every other SDK derives. Refused rather than returned.
      throw StateError(
        'falcon-512 key generation read $consumed random bytes, '
        'expected $seedBytes - this liboqs build does not derive portable '
        'keys from a seed',
      );
    }
    return _checked(pair.publicKey, pair.secretKey);
  }

  @override
  Uint8List sign(Uint8List message, Uint8List privateKey) {
    _checkLength(privateKey, privateKeyBytes, privateHeader, 'private');
    return _sig.sign(message, privateKey);
  }

  @override
  bool verify(Uint8List message, Uint8List signature, Uint8List publicKey) {
    if (publicKey.length != publicKeyBytes || publicKey[0] != publicHeader) {
      return false;
    }
    if (signature.isEmpty || signature[0] != signatureHeader) return false;
    try {
      return _sig.verify(message, signature, publicKey);
    } catch (_) {
      return false;
    }
  }

  ({Uint8List publicKey, Uint8List privateKey}) _checked(
    Uint8List publicKey,
    Uint8List privateKey,
  ) {
    _checkLength(publicKey, publicKeyBytes, publicHeader, 'public');
    _checkLength(privateKey, privateKeyBytes, privateHeader, 'private');
    return (publicKey: publicKey, privateKey: privateKey);
  }

  static void _checkLength(
    Uint8List bytes,
    int expected,
    int header,
    String what,
  ) {
    // A key "one byte off" - BouncyCastle strips the header, for one - is
    // reported by the ledger as 1220 "Signature Incorrect", a message about
    // signatures for a problem about key length. So it fails here instead.
    if (bytes.length != expected) {
      throw ArgumentError(
        'falcon-512 $what key should be $expected bytes, got '
        '${bytes.length}${bytes.length == expected - 1 ? ' - this looks like '
                  'a key with its header byte stripped' : ''}',
      );
    }
    if (bytes[0] != header) {
      throw ArgumentError(
        'falcon-512 $what key should start with 0x'
        '${header.toRadixString(16).padLeft(2, '0')}, got 0x'
        '${bytes[0].toRadixString(16).padLeft(2, '0')}',
      );
    }
  }
}

/// The byte source liboqs reads from during seeded key generation.
abstract final class _SeededRandom {
  static Uint8List? _seed;
  static int _position = 0;

  static void begin(Uint8List seed) {
    _seed = seed;
    _position = 0;
  }

  static int end() {
    final consumed = _position;
    _seed = null;
    _position = 0;
    return consumed;
  }

  static void fill(Pointer<Uint8> out, int length) {
    final seed = _seed!;
    for (var i = 0; i < length; i++) {
      // Past the end of the seed the bytes are still well-defined, so
      // nothing reads uninitialised memory; end() then reports the overrun.
      out[i] = seed[_position++ % seed.length];
    }
  }
}
