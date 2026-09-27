import 'dart:convert';
import 'dart:typed_data';

/// Serialises [value] exactly as JavaScript's `JSON.stringify` would.
///
/// Activeledger signs the exact bytes of `JSON.stringify($tx)` encoded UTF-8
/// - no hash prefix, no length prefix and no key sorting - and the ledger
/// verifies by re-stringifying the `$tx` it parsed. A signature over bytes
/// that differ by one escape is simply invalid, and the ledger reports it as
/// 1220 "Signature Incorrect", which says nothing about serialisation.
///
/// `dart:convert`'s `jsonEncode` disagrees with JavaScript in ways that are
/// all invisible on an ASCII-only integer payload:
///
/// | Input          | `jsonEncode`         | `JSON.stringify` |
/// |----------------|----------------------|------------------|
/// | `1.0`          | `1.0`                | `1`              |
/// | `1e21`         | `1e+21`              | `1e+21`          |
/// | `1e20`         | `100000000000000000000.0` | `100000000000000000000` |
/// | `2^53 + 1`     | `9007199254740993`   | `9007199254740992` |
///
/// Accepted values: `null`, `bool`, `num`, `String`, `Map` with `String`
/// keys (insertion order is kept, as JavaScript keeps it), `Iterable`, and
/// any object with a `toJson()` method, which is called the way
/// `JSON.stringify` calls `toJSON()`.
///
/// Refused rather than silently rewritten: `NaN` and infinities (JavaScript
/// writes `null`, which would sign bytes you did not write) and integers
/// that a JavaScript number cannot hold exactly (the ledger would store a
/// different value from the one you passed).
String canonicalJson(Object? value) {
  final out = StringBuffer();
  _write(value, out, 0);
  return out.toString();
}

/// The UTF-8 bytes of [canonicalJson] - what actually gets signed.
Uint8List canonicalJsonBytes(Object? value) =>
    Uint8List.fromList(utf8.encode(canonicalJson(value)));

const _maxDepth = 512;

void _write(Object? value, StringBuffer out, int depth) {
  if (depth > _maxDepth) {
    throw ArgumentError(
      'JSON nesting is deeper than $_maxDepth - is there a '
      'cycle?',
    );
  }

  if (value == null) {
    out.write('null');
  } else if (value is bool) {
    out.write(value ? 'true' : 'false');
  } else if (value is String) {
    _writeString(value, out);
  } else if (value is int) {
    out.write(_jsInteger(value));
  } else if (value is double) {
    out.write(jsNumber(value));
  } else if (value is Map) {
    out.write('{');
    var first = true;
    for (final entry in value.entries) {
      final key = entry.key;
      if (key is! String) {
        throw ArgumentError.value(
          key,
          'key',
          'JSON object keys must be strings, got ${key.runtimeType}',
        );
      }
      if (!first) out.write(',');
      first = false;
      _writeString(key, out);
      out.write(':');
      _write(entry.value, out, depth + 1);
    }
    out.write('}');
  } else if (value is Iterable) {
    out.write('[');
    var first = true;
    for (final item in value) {
      if (!first) out.write(',');
      first = false;
      _write(item, out, depth + 1);
    }
    out.write(']');
  } else {
    Object? converted;
    try {
      // ignore: avoid_dynamic_calls
      converted = (value as dynamic).toJson();
    } on NoSuchMethodError {
      throw ArgumentError.value(
        value,
        'value',
        'Cannot serialise ${value.runtimeType} - give it a toJson() method or '
            'convert it to a Map first. What gets signed is these exact bytes, '
            'so an inferred conversion would be a silent risk.',
      );
    }
    _write(converted, out, depth + 1);
  }
}

/// An integer as JavaScript would print it after parsing it into a double.
String _jsInteger(int value) {
  final asDouble = value.toDouble();
  if (BigInt.from(asDouble) != BigInt.from(value)) {
    throw ArgumentError.value(
      value,
      'value',
      'This integer cannot be represented exactly as a JavaScript number. The '
          'ledger would parse it as ${jsNumber(asDouble)} - a different value '
          'from the one given - so it is refused. Send it as a string.',
    );
  }
  return jsNumber(asDouble);
}

/// Formats a number exactly as JavaScript's `Number.prototype.toString` (and
/// therefore `JSON.stringify`) would.
///
/// Implements ECMA-262 Number::toString:
///
/// - negative zero prints as `0`;
/// - plain decimal while the decimal exponent n satisfies -6 < n <= 21, so
///   1e20 is `100000000000000000000` and 1e21 is `1e+21`;
/// - the exponent has no leading zeros and an explicit `+` when positive;
/// - the digits are the SHORTEST decimal that round-trips to the same double.
///
/// Checked against the cross-language `number-vectors.json`.
String jsNumber(double value) {
  if (value.isNaN || value.isInfinite) {
    throw ArgumentError.value(
      value,
      'value',
      '$value cannot be serialised - JSON.stringify emits null, which would '
          'sign bytes you did not intend',
    );
  }
  if (value == 0) return '0'; // covers -0.0
  if (value < 0) return '-${jsNumber(-value)}';

  // Dart's shortest round-tripping form, e.g. "1.2345e+2" or "5e-324".
  final text = value.toStringAsExponential();
  final split = text.indexOf('e');
  final mantissa = text.substring(0, split);
  final exponent = int.parse(text.substring(split + 1));

  var digits = mantissa.replaceAll('.', '');
  digits = digits.replaceFirst(RegExp(r'0+$'), '');
  if (digits.isEmpty) digits = '0';
  final k = digits.length;
  final n = exponent + 1; // value == 0.<digits> * 10^n

  if (k <= n && n <= 21) return digits + '0' * (n - k);
  if (0 < n && n <= 21) {
    return '${digits.substring(0, n)}.${digits.substring(n)}';
  }
  if (-6 < n && n <= 0) return '0.${'0' * -n}$digits';

  final e = n - 1;
  final head = k == 1 ? digits : '${digits[0]}.${digits.substring(1)}';
  return '${head}e${e >= 0 ? '+' : '-'}${e.abs()}';
}

/// String escaping, matching JSON.stringify exactly.
///
/// Escapes `"` and `\`, the control characters below 0x20 (using the short
/// forms where JavaScript has them), and lone UTF-16 surrogates, which
/// JavaScript has escaped since ES2019. Everything else - all other
/// non-ASCII, including U+2028 and U+2029 - passes through as raw UTF-8.
void _writeString(String value, StringBuffer out) {
  out.write('"');
  final units = value.codeUnits;
  for (var i = 0; i < units.length; i++) {
    final c = units[i];
    switch (c) {
      case 0x22:
        out.write(r'\"');
      case 0x5c:
        out.write(r'\\');
      case 0x0a:
        out.write(r'\n');
      case 0x0d:
        out.write(r'\r');
      case 0x09:
        out.write(r'\t');
      case 0x08:
        out.write(r'\b');
      case 0x0c:
        out.write(r'\f');
      default:
        if (c < 0x20) {
          out.write(r'\u');
          out.write(c.toRadixString(16).padLeft(4, '0'));
        } else if (c >= 0xd800 && c <= 0xdbff) {
          // A high surrogate is only well-formed followed by a low one.
          if (i + 1 < units.length &&
              units[i + 1] >= 0xdc00 &&
              units[i + 1] <= 0xdfff) {
            out.writeCharCode(c);
            out.writeCharCode(units[++i]);
          } else {
            out.write(r'\u');
            out.write(c.toRadixString(16));
          }
        } else if (c >= 0xdc00 && c <= 0xdfff) {
          out.write(r'\u');
          out.write(c.toRadixString(16));
        } else {
          out.writeCharCode(c);
        }
    }
  }
  out.write('"');
}
