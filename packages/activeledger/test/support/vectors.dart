import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

/// Loads one of the cross-language vector files from the repository's
/// `vectors/` directory. They are copied unmodified from the JavaScript SDK,
/// which generates them.
Map<String, Object?> loadVectors(String name) {
  for (final dir in ['../../vectors', 'vectors']) {
    final file = File('$dir/$name');
    if (file.existsSync()) {
      return (jsonDecode(file.readAsStringSync()) as Map)
          .cast<String, Object?>();
    }
  }
  throw StateError(
    'Cannot find vectors/$name - run tests from the package directory',
  );
}

List<Map<String, Object?>> vectorList(Map<String, Object?> file, String key) =>
    [
      for (final v in file[key]! as List<Object?>)
        (v! as Map).cast<String, Object?>(),
    ];

Uint8List hexBytes(String hex) => Uint8List.fromList([
  for (var i = 0; i < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
]);

String toHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
