import 'dart:typed_data';

import 'package:activeledger/src/crypto/der.dart';
import 'package:test/test.dart';

/// The DER reader and writer behind signatures and PEM keys. Expected bytes
/// are written out by hand from X.690, not produced by the code under test.
Uint8List bytes(List<int> values) => Uint8List.fromList(values);

void main() {
  group('derLength', () {
    test('short form below 128', () {
      expect(derLength(0), [0x00]);
      expect(derLength(127), [0x7f]);
    });

    test('long form from 128, with the minimum number of length bytes', () {
      expect(derLength(128), [0x81, 0x80]);
      expect(derLength(255), [0x81, 0xff]);
      expect(derLength(256), [0x82, 0x01, 0x00]);
      expect(derLength(65535), [0x82, 0xff, 0xff]);
      expect(derLength(65536), [0x83, 0x01, 0x00, 0x00]);
    });
  });

  group('derInteger', () {
    test('zero is one zero byte', () {
      expect(derInteger(BigInt.zero), [0x02, 0x01, 0x00]);
    });

    test('a high bit gets a leading zero so it stays positive', () {
      expect(derInteger(BigInt.from(0x7f)), [0x02, 0x01, 0x7f]);
      expect(derInteger(BigInt.from(0x80)), [0x02, 0x02, 0x00, 0x80]);
      expect(derInteger(BigInt.from(0x100)), [0x02, 0x02, 0x01, 0x00]);
    });
  });

  test('derSequence wraps already encoded elements', () {
    expect(derSequence([derInteger(BigInt.one), derInteger(BigInt.two)]), [
      0x30,
      0x06,
      0x02,
      0x01,
      0x01,
      0x02,
      0x01,
      0x02,
    ]);
    expect(derSequence([]), [0x30, 0x00]);
  });

  test('a sequence longer than 127 bytes uses the long length form', () {
    final big = BigInt.one << 1100; // 138 bytes of INTEGER body
    final encoded = derSequence([derInteger(big)]);
    expect(encoded.sublist(0, 4), [0x30, 0x81, 0x8d, 0x02]);
    final parsed = DerElement.parse(encoded).children.single;
    expect(parsed.asUnsignedInt, big);
  });

  group('integer byte conversions', () {
    test('bytesToBigInt is big-endian and ignores leading zeros', () {
      expect(bytesToBigInt([0x01, 0x00]), BigInt.from(256));
      expect(bytesToBigInt([0x00, 0x00, 0x2a]), BigInt.from(42));
      expect(bytesToBigInt([]), BigInt.zero);
    });

    test('bigIntToBytes is minimal and empty for zero', () {
      expect(bigIntToBytes(BigInt.zero), isEmpty);
      expect(bigIntToBytes(BigInt.from(255)), [0xff]);
      expect(bigIntToBytes(BigInt.from(256)), [0x01, 0x00]);
    });

    test('bigIntToBytes refuses a negative value', () {
      expect(() => bigIntToBytes(BigInt.from(-1)), throwsArgumentError);
    });

    test('bigIntToFixed left-pads to the requested width', () {
      expect(bigIntToFixed(BigInt.from(0x0102), 4), [0, 0, 1, 2]);
      expect(bigIntToFixed(BigInt.zero, 3), [0, 0, 0]);
      expect(bigIntToFixed(BigInt.from(0x010203), 3), [1, 2, 3]);
    });

    test('bigIntToFixed refuses a value that does not fit', () {
      expect(
        () => bigIntToFixed(BigInt.from(0x010203), 2),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('needs 3 bytes'),
          ),
        ),
      );
    });
  });

  group('DerElement.parse', () {
    test('reads tag and content', () {
      final e = DerElement.parse(bytes([0x04, 0x02, 0xca, 0xfe]));
      expect(e.tag, DerElement.octetString);
      expect(e.content, [0xca, 0xfe]);
    });

    test('reads a long-form length', () {
      final body = List<int>.generate(200, (i) => i);
      final e = DerElement.parse(bytes([0x04, 0x81, 200, ...body]));
      expect(e.content, body);
      final e2 = DerElement.parse(
        bytes([0x04, 0x82, 0x01, 0x00, ...body, ...body.take(56)]),
      );
      expect(e2.content.length, 256);
    });

    test('refuses a header cut short', () {
      expect(
        () => DerElement.parse(bytes([0x30])),
        throwsA(isA<FormatException>()),
      );
      expect(() => DerElement.parse(bytes([])), throwsFormatException);
    });

    test('refuses indefinite and oversized length encodings', () {
      expect(
        () => DerElement.parse(bytes([0x30, 0x80, 0x00, 0x00])),
        throwsA(
          isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('unsupported length'),
          ),
        ),
      );
      expect(
        () => DerElement.parse(bytes([0x30, 0x85, 1, 0, 0, 0, 0])),
        throwsFormatException,
      );
    });

    test('refuses a long-form length whose bytes are missing', () {
      expect(
        () => DerElement.parse(bytes([0x30, 0x82, 0x01])),
        throwsA(
          isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('truncated length'),
          ),
        ),
      );
    });

    test('refuses an element that runs past the end', () {
      expect(
        () => DerElement.parse(bytes([0x04, 0x05, 0x01, 0x02])),
        throwsA(
          isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('past the end'),
          ),
        ),
      );
    });

    test('refuses trailing bytes after the element', () {
      expect(
        () => DerElement.parse(bytes([0x02, 0x01, 0x01, 0x00])),
        throwsA(
          isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('trailing'),
          ),
        ),
      );
    });
  });

  group('DerElement.children', () {
    test('lists nested elements in order', () {
      final seq = DerElement.parse(
        bytes([0x30, 0x07, 0x02, 0x01, 0x05, 0x30, 0x02, 0x05, 0x00]),
      );
      final kids = seq.children;
      expect(kids.map((k) => k.tag), [DerElement.integer, DerElement.sequence]);
      expect(kids[1].children.single.tag, DerElement.nullTag);
    });

    test('a child that overruns its parent is refused', () {
      final seq = DerElement.parse(bytes([0x30, 0x03, 0x02, 0x05, 0x01]));
      expect(() => seq.children, throwsFormatException);
    });
  });

  group('DerElement.asUnsignedInt', () {
    test('reads big values', () {
      expect(
        DerElement.parse(bytes([0x02, 0x02, 0x00, 0x80])).asUnsignedInt,
        BigInt.from(128),
      );
    });

    test('refuses a non-INTEGER, an empty INTEGER and a negative one', () {
      expect(
        () => DerElement.parse(bytes([0x04, 0x01, 0x01])).asUnsignedInt,
        throwsFormatException,
      );
      expect(
        () => DerElement.parse(bytes([0x02, 0x00])).asUnsignedInt,
        throwsFormatException,
      );
      expect(
        () => DerElement.parse(bytes([0x02, 0x01, 0x80])).asUnsignedInt,
        throwsA(
          isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('negative'),
          ),
        ),
      );
    });
  });

  group('DerElement.asOid', () {
    String oid(List<int> content) =>
        DerElement.parse(bytes([0x06, content.length, ...content])).asOid;

    test('decodes the OIDs this SDK recognises', () {
      expect(
        oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
        '1.2.840.113549.1.1.1',
      );
      expect(
        oid([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
        '1.2.840.10045.2.1',
      );
      expect(oid([0x2b, 0x81, 0x04, 0x00, 0x0a]), '1.3.132.0.10');
    });

    test('an arc under 2 packs the first two components into one byte', () {
      expect(oid([0x55, 0x04, 0x03]), '2.5.4.3');
    });

    test('a first byte of 80 or more means arc 2 with a large second', () {
      // 2.999 is 40*2+999 = 1079 = 0x88 0x37 in base-128.
      expect(oid([0x88, 0x37]), '2.999');
    });

    test('refuses a non-OID', () {
      expect(
        () => DerElement.parse(bytes([0x04, 0x01, 0x2a])).asOid,
        throwsFormatException,
      );
    });
  });

  group('PemBlock', () {
    test('parses label and DER, ignoring line breaks and indentation', () {
      final block = PemBlock.parse(
        '-----BEGIN TEST KEY-----\n  AQID\r\n  BA==\n-----END TEST KEY-----\n',
      );
      expect(block.label, 'TEST KEY');
      expect(block.der, [1, 2, 3, 4]);
    });

    test('finds the block inside surrounding text', () {
      final block = PemBlock.parse(
        'noise\n-----BEGIN X-----\nAQ==\n-----END X-----\ntrailer',
      );
      expect(block.der, [1]);
    });

    test('refuses text with no block, or mismatched BEGIN and END labels', () {
      expect(() => PemBlock.parse('AQID'), throwsFormatException);
      expect(
        () => PemBlock.parse('-----BEGIN A-----\nAQ==\n-----END B-----'),
        throwsFormatException,
      );
    });

    test('refuses a body that is not base64', () {
      expect(
        () => PemBlock.parse('-----BEGIN A-----\n!!!!\n-----END A-----'),
        throwsFormatException,
      );
    });

    test('looksLikePem tells PEM from hex and base64', () {
      expect(PemBlock.looksLikePem('-----BEGIN PUBLIC KEY-----'), isTrue);
      expect(PemBlock.looksLikePem('0xabcdef'), isFalse);
      expect(PemBlock.looksLikePem('QUJD'), isFalse);
    });
  });
}
