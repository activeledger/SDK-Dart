/// Falcon-512 for the Activeledger Dart SDK.
///
/// ```dart
/// import 'package:activeledger_falcon/activeledger_falcon.dart';
///
/// void main() {
///   ActiveledgerFalcon.enable();
///   final key = KeyHandler().generateKey('me', type: KeyType.preferredPostQuantum);
/// }
/// ```
///
/// Re-exports `package:activeledger`, so this one import is enough.
library;

import 'dart:typed_data';

import 'package:activeledger/activeledger.dart';

import 'src/falcon512.dart';

export 'package:activeledger/activeledger.dart';
export 'src/falcon512.dart' show Falcon512Scheme;

/// Turns Falcon-512 on for the whole SDK.
abstract final class ActiveledgerFalcon {
  static bool _enabled = false;
  static Object? _failure;

  /// Registers Falcon-512 with the SDK, returning whether it is available.
  ///
  /// Loads liboqs's native library (bundled with the package for Android,
  /// iOS, macOS, Linux and Windows), runs a sign-and-verify self-test, and
  /// registers the scheme. After that, `KeyType.falcon512` works everywhere
  /// and `KeyType.preferredPostQuantum` resolves to it.
  ///
  /// If the native library cannot be loaded this returns false and leaves
  /// the SDK on ML-DSA-65 - or throws, when [throwOnFailure] is set. Safe to
  /// call more than once.
  static bool enable({bool throwOnFailure = false}) {
    if (_enabled) return true;
    try {
      final scheme = Falcon512Scheme();
      final keys = scheme.generate();
      final message = Uint8List.fromList('activeledger'.codeUnits);
      final signature = scheme.sign(message, keys.privateKey);
      if (!scheme.verify(message, signature, keys.publicKey)) {
        throw StateError('falcon-512 self-test failed');
      }
      PostQuantum.register(scheme);
      _enabled = true;
      _failure = null;
      return true;
    } catch (error) {
      _failure = error;
      if (throwOnFailure) rethrow;
      return false;
    }
  }

  /// Whether [enable] succeeded.
  static bool get isEnabled => _enabled;

  /// Why the last [enable] failed, if it did.
  static Object? get failure => _failure;

  /// Unregisters Falcon-512.
  static void disable() {
    PostQuantum.unregister(KeyType.falcon512);
    _enabled = false;
  }
}
