import 'dart:convert';

import 'package:activeledger/activeledger.dart';
import 'package:test/test.dart';

import 'support/vectors.dart';

void main() {
  group('number-vectors.json', () {
    final file = loadVectors('number-vectors.json');
    for (final v in vectorList(file, 'vectors')) {
      test(v['name'], () {
        final value = v['value']! as num;
        final input = v['name'] == 'negative-zero' ? -0.0 : value.toDouble();
        expect(jsNumber(input), v['expected']);
        expect(canonicalJson(input), v['expected']);
      });
    }
  });

  group('pq-vectors.json messages round-trip through Dart', () {
    // Each message is JSON.stringify output. Parsing it with dart:convert
    // and re-serialising must give the same bytes back, or a Dart caller
    // building the same object would sign something else.
    final file = loadVectors('pq-vectors.json');
    final seen = <String>{};
    for (final v in vectorList(file, 'vectors')) {
      if (!seen.add(v['messageName']! as String)) continue;
      test(v['messageName'], () {
        final message = v['message']! as String;
        expect(canonicalJson(jsonDecode(message)), message);
      });
    }
  });

  group('canonicalJson', () {
    test('keeps insertion order, adds no whitespace', () {
      expect(
        canonicalJson({
          'zebra': 1,
          'alpha': 2,
          'middle': [true, null],
        }),
        '{"zebra":1,"alpha":2,"middle":[true,null]}',
      );
    });

    test('does not escape non-ASCII or HTML characters', () {
      expect(
        canonicalJson({'s': 'café <b>&</b>   ☕'}),
        '{"s":"café <b>&</b>   ☕"}',
      );
    });

    test('escapes as JSON.stringify does', () {
      expect(
        canonicalJson('"\\\n\r\t\b\f\u0001\u001f'),
        r'"\"\\\n\r\t\b\f\u0001\u001f"',
      );
    });

    test('escapes lone surrogates, keeps pairs', () {
      expect(canonicalJson('\u{1F600}'), '"\u{1F600}"');
      expect(canonicalJson(String.fromCharCode(0xd800)), r'"\ud800"');
      expect(canonicalJson(String.fromCharCode(0xdc00)), r'"\udc00"');
    });

    test('whole doubles print without .0', () {
      expect(
        canonicalJson({'a': 1.0, 'b': 1e20, 'c': -0.0}),
        '{"a":1,"b":100000000000000000000,"c":0}',
      );
    });

    test('integers print as JavaScript numbers', () {
      expect(
        canonicalJson(1 << 60),
        '1152921504606847000',
      ); // as node prints it
      expect(canonicalJson(9007199254740991), '9007199254740991');
    });

    test('refuses integers JavaScript would round', () {
      expect(() => canonicalJson(9007199254740993), throwsArgumentError);
    });

    test('refuses NaN and infinities', () {
      expect(() => canonicalJson(double.nan), throwsArgumentError);
      expect(() => canonicalJson(double.infinity), throwsArgumentError);
    });

    test('refuses non-string keys and unknown objects', () {
      expect(() => canonicalJson({1: 'a'}), throwsArgumentError);
      expect(() => canonicalJson(Object()), throwsArgumentError);
    });

    test('calls toJson()', () {
      expect(canonicalJson({'k': _WithToJson()}), '{"k":{"x":1}}');
    });
  });
}

class _WithToJson {
  Map<String, Object?> toJson() => {'x': 1};
}
