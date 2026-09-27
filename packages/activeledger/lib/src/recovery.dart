import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';
import 'package:unorm_dart/unorm_dart.dart' as unorm;

import 'bip39_english.dart';
import 'crypto/random.dart';
import 'key_type.dart';

/// BIP-39 recovery phrases, and the seed each key type derives from one.
///
/// Two layers, and conflating them is the mistake this is arranged to
/// prevent. A phrase becomes a 64-byte BIP-39 seed ([toSeed]); that seed
/// becomes the seed the chosen algorithm actually takes ([deriveSeed]).
///
/// ```text
/// BIP-39 seed S = PBKDF2-HMAC-SHA512(phrase, "mnemonic" + passphrase, 2048, 64)
///
/// ml-dsa-65   HKDF-SHA512(S, salt="", info="activeledger-seed-v1:ml-dsa-65", 32)
/// falcon-512  HKDF-SHA512(S, salt="", info="activeledger-seed-v1:falcon-512", 48)
/// secp256k1   HMAC-SHA512("Bitcoin seed", S)[0..32]
/// ```
///
/// secp256k1 does not use HKDF, and that is not an oversight: the JavaScript
/// SDK shipped that derivation before the post-quantum types existed, so
/// phrases are already in use and changing it would hand those users a
/// different key for a phrase that used to work.
///
/// Identical in every Activeledger SDK, and checked here against the
/// cross-language `seed-vectors.json`.
abstract final class Recovery {
  /// A BIP-39 seed is always 64 bytes.
  static const int bip39SeedBytes = 64;

  /// BIP-39's fixed iteration count. Changing it changes every identity.
  static const int _iterations = 2048;

  /// Each algorithm's own seed length.
  static const Map<KeyType, int> seedSizes = {
    KeyType.secp256k1: 32,
    KeyType.mlDsa65: 32,
    KeyType.falcon512: 48,
  };

  static final Map<String, int> _wordIndex = {
    for (var i = 0; i < bip39English.length; i++) bip39English[i]: i,
  };

  /// The seed length [type] takes.
  static int seedSize(KeyType type) {
    final size = seedSizes[type];
    if (size == null) {
      throw ArgumentError('${type.wire} keys cannot be derived from a seed');
    }
    return size;
  }

  /// A new random English mnemonic. [strength] is the entropy in bits: 128
  /// (12 words, the default), 160, 192, 224 or 256 (24 words).
  static String generateMnemonic({int strength = 128}) {
    if (strength < 128 || strength > 256 || strength % 32 != 0) {
      throw ArgumentError.value(
        strength,
        'strength',
        'must be 128, 160, 192, 224 or 256',
      );
    }
    final entropy = secureRandomBytes(strength ~/ 8);
    final hash = SHA256Digest().process(entropy);
    final bits = StringBuffer();
    for (final b in entropy) {
      bits.write(b.toRadixString(2).padLeft(8, '0'));
    }
    final checksum = hash[0].toRadixString(2).padLeft(8, '0');
    bits.write(checksum.substring(0, strength ~/ 32));
    final all = bits.toString();
    return [
      for (var i = 0; i < all.length; i += 11)
        bip39English[int.parse(all.substring(i, i + 11), radix: 2)],
    ].join(' ');
  }

  /// Checks a phrase - wordlist AND checksum - and returns it normalised and
  /// single-spaced.
  ///
  /// A mistyped phrase that is not checked does not fail: it derives a
  /// perfectly valid key for an identity nobody owns, and the only symptom
  /// is the ledger not recognising it.
  static String validate(String phrase) {
    final words = unorm
        .nfkd(phrase)
        .split(RegExp(r'\s+'))
        .where((w) => w.isNotEmpty)
        .toList();

    // 12, 15, 18, 21 and 24 are the only valid lengths.
    if (words.length < 12 || words.length > 24 || words.length % 3 != 0) {
      throw ArgumentError(
        'a BIP-39 phrase is 12, 15, 18, 21 or 24 words, got ${words.length}',
      );
    }

    final bits = StringBuffer();
    for (var i = 0; i < words.length; i++) {
      // Checked before the checksum so the error names the offending word
      // rather than blaming the checksum for a typo the caller can see.
      final index = _wordIndex[words[i]];
      if (index == null) {
        throw ArgumentError(
          'word ${i + 1} ("${words[i]}") is not in the '
          'BIP-39 English wordlist',
        );
      }
      bits.write(index.toRadixString(2).padLeft(11, '0'));
    }

    final all = bits.toString();
    final checksumBits = words.length ~/ 3;
    final entropyBits = all.length - checksumBits;
    final entropy = Uint8List(entropyBits ~/ 8);
    for (var i = 0; i < entropy.length; i++) {
      entropy[i] = int.parse(all.substring(i * 8, i * 8 + 8), radix: 2);
    }
    final hash = SHA256Digest().process(entropy);
    final expected = hash[0]
        .toRadixString(2)
        .padLeft(8, '0')
        .substring(0, checksumBits);

    if (all.substring(entropyBits) != expected) {
      throw ArgumentError(
        'the BIP-39 checksum does not match - the phrase has a typo or the '
        'words are in the wrong order. Deriving from it anyway would '
        'produce a valid key for an identity nobody owns. If you meant to '
        'derive from a non-mnemonic string, pass validate: false.',
      );
    }

    return words.join(' ');
  }

  /// Turns a recovery phrase into its 64-byte BIP-39 seed.
  ///
  /// Validates by default, as every Activeledger SDK does. Pass
  /// `validate: false` only to derive from a string that is not a BIP-39
  /// mnemonic.
  static Uint8List toSeed(
    String phrase, {
    String passphrase = '',
    bool validate = true,
  }) {
    final checked = validate ? Recovery.validate(phrase) : unorm.nfkd(phrase);
    final derivator = PBKDF2KeyDerivator(HMac(SHA512Digest(), 128))
      ..init(
        Pbkdf2Parameters(
          // BIP-39's salt: the passphrase is appended to the literal
          // "mnemonic", not passed separately.
          Uint8List.fromList(utf8.encode('mnemonic${unorm.nfkd(passphrase)}')),
          _iterations,
          bip39SeedBytes,
        ),
      );
    return derivator.process(Uint8List.fromList(utf8.encode(checked)));
  }

  /// Turns a 64-byte BIP-39 seed into the seed [type] takes.
  ///
  /// Hand the result to `KeyHandler.generateKeyFromSeed`, or to another SDK:
  /// falcon-512's seed derives here even where Falcon itself is unavailable.
  static Uint8List deriveSeed(KeyType type, Uint8List bip39Seed) {
    if (bip39Seed.length != bip39SeedBytes) {
      throw ArgumentError(
        'a BIP-39 seed is $bip39SeedBytes bytes, got ${bip39Seed.length}',
      );
    }
    final size = seedSize(type);

    if (type == KeyType.secp256k1) return deriveBip32MasterKey(bip39Seed);

    // An empty salt is a block of zero bytes of the hash length, which is
    // what RFC 5869 specifies.
    final hkdf = HKDFKeyDerivator(SHA512Digest())
      ..init(
        HkdfParameters(
          bip39Seed,
          size,
          Uint8List(0),
          Uint8List.fromList(utf8.encode('activeledger-seed-v1:${type.wire}')),
        ),
      );
    final out = Uint8List(size);
    hkdf.deriveKey(null, 0, out, 0);
    return out;
  }

  /// BIP-32's master key step applied to a BIP-39 seed - and nothing past
  /// that root, since no child paths are derived. This is the whole of the
  /// secp256k1 derivation.
  ///
  /// Another client in the wild derives a BIP-32 CHILD at `m/44'/1'/0'/0/0`
  /// instead, which is a different identity from the same phrase.
  static Uint8List deriveBip32MasterKey(Uint8List bip39Seed) {
    final mac = HMac(SHA512Digest(), 128)
      ..init(KeyParameter(Uint8List.fromList(utf8.encode('Bitcoin seed'))));
    return Uint8List.sublistView(mac.process(bip39Seed), 0, 32);
  }

  /// The legacy scheme: SHA256(phrase) used directly as a secp256k1 scalar.
  ///
  /// No key stretching, no domain separation, no passphrase. It exists so a
  /// phrase made by `@activeledger/sdk-bip39` can be RECOVERED, never so a
  /// new key can be made with it. Deliberately does not validate the
  /// mnemonic: the original package never consulted the wordlist.
  static Uint8List legacySeed(String phrase) =>
      SHA256Digest().process(Uint8List.fromList(utf8.encode(phrase)));
}
