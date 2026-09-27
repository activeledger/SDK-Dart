import 'dart:convert';
import 'dart:typed_data';

/// Just enough DER to read and write the structures this SDK touches: ECDSA
/// signatures and the PEM key formats OpenSSL produces for RSA and
/// secp256k1. Strict: indefinite lengths and trailing bytes are refused.
class DerElement {
  DerElement(this.tag, this.content);

  final int tag;
  final Uint8List content;

  static const int integer = 0x02;
  static const int bitString = 0x03;
  static const int octetString = 0x04;
  static const int nullTag = 0x05;
  static const int oid = 0x06;
  static const int sequence = 0x30;

  /// Parses exactly one element spanning all of [bytes].
  static DerElement parse(Uint8List bytes) {
    final (element, end) = _read(bytes, 0);
    if (end != bytes.length) {
      throw const FormatException('DER: trailing bytes after element');
    }
    return element;
  }

  /// The children of a constructed element (SEQUENCE, context tags).
  List<DerElement> get children {
    final out = <DerElement>[];
    var offset = 0;
    while (offset < content.length) {
      final (element, end) = _read(content, offset);
      out.add(element);
      offset = end;
    }
    return out;
  }

  /// This INTEGER as a non-negative BigInt.
  BigInt get asUnsignedInt {
    if (tag != integer) throw const FormatException('DER: expected INTEGER');
    if (content.isEmpty) throw const FormatException('DER: empty INTEGER');
    if (content[0] & 0x80 != 0) {
      throw const FormatException('DER: negative INTEGER');
    }
    return bytesToBigInt(content);
  }

  /// This OBJECT IDENTIFIER in dotted form.
  String get asOid {
    if (tag != oid) throw const FormatException('DER: expected OID');
    final parts = <int>[];
    var value = 0;
    for (final b in content) {
      value = (value << 7) | (b & 0x7f);
      if (b & 0x80 == 0) {
        if (parts.isEmpty) {
          final first = value < 80 ? value ~/ 40 : 2;
          parts
            ..add(first)
            ..add(value - first * 40);
        } else {
          parts.add(value);
        }
        value = 0;
      }
    }
    return parts.join('.');
  }

  static (DerElement, int) _read(Uint8List bytes, int offset) {
    if (offset + 2 > bytes.length) {
      throw const FormatException('DER: truncated header');
    }
    final tag = bytes[offset];
    var length = bytes[offset + 1];
    var pos = offset + 2;
    if (length & 0x80 != 0) {
      final count = length & 0x7f;
      if (count == 0 || count > 4) {
        throw const FormatException('DER: unsupported length encoding');
      }
      if (pos + count > bytes.length) {
        throw const FormatException('DER: truncated length');
      }
      length = 0;
      for (var i = 0; i < count; i++) {
        length = (length << 8) | bytes[pos++];
      }
    }
    final end = pos + length;
    if (end > bytes.length) {
      throw const FormatException('DER: element runs past the end');
    }
    return (DerElement(tag, Uint8List.sublistView(bytes, pos, end)), end);
  }
}

/// Encodes a DER length.
List<int> derLength(int length) {
  if (length < 0x80) return [length];
  final out = <int>[];
  var n = length;
  while (n > 0) {
    out.insert(0, n & 0xff);
    n >>= 8;
  }
  return [0x80 | out.length, ...out];
}

/// A minimal DER INTEGER for a non-negative value.
Uint8List derInteger(BigInt value) {
  var body = bigIntToBytes(value);
  if (body.isEmpty) body = Uint8List(1);
  if (body[0] & 0x80 != 0) body = Uint8List.fromList([0, ...body]);
  return Uint8List.fromList([
    DerElement.integer,
    ...derLength(body.length),
    ...body,
  ]);
}

/// A DER SEQUENCE of already-encoded elements.
Uint8List derSequence(List<Uint8List> elements) {
  final body = elements.expand((e) => e).toList();
  return Uint8List.fromList([
    DerElement.sequence,
    ...derLength(body.length),
    ...body,
  ]);
}

/// Big-endian unsigned bytes to BigInt.
BigInt bytesToBigInt(List<int> bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

/// BigInt to minimal big-endian unsigned bytes (empty for zero).
Uint8List bigIntToBytes(BigInt value) {
  if (value.isNegative) throw ArgumentError('negative value');
  final out = <int>[];
  var n = value;
  final mask = BigInt.from(0xff);
  while (n > BigInt.zero) {
    out.insert(0, (n & mask).toInt());
    n >>= 8;
  }
  return Uint8List.fromList(out);
}

/// BigInt to exactly [length] big-endian bytes, left-padded with zeros.
Uint8List bigIntToFixed(BigInt value, int length) {
  final raw = bigIntToBytes(value);
  if (raw.length > length) {
    throw ArgumentError('value needs ${raw.length} bytes, more than $length');
  }
  return Uint8List(length)..setRange(length - raw.length, length, raw);
}

/// A decoded PEM block.
class PemBlock {
  PemBlock(this.label, this.der);

  final String label;
  final Uint8List der;

  static final _pattern = RegExp(
    r'-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----',
  );

  /// Whether [text] looks like PEM rather than hex or base64.
  static bool looksLikePem(String text) => text.contains('-----BEGIN ');

  static PemBlock parse(String text) {
    final match = _pattern.firstMatch(text);
    if (match == null) throw const FormatException('Not a PEM block');
    final body = match.group(2)!.replaceAll(RegExp(r'\s'), '');
    return PemBlock(match.group(1)!, Uint8List.fromList(base64.decode(body)));
  }
}
