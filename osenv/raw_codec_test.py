"""Independent exhaustive parse oracle and strict malformed-stream regressions."""
from functools import lru_cache
from itertools import product
import unittest
from .raw_codec import encode, decode


def oracle(data):
    """Exhaust every legal distance/length; do not reuse encoder match selection."""
    @lru_cache(None)
    def visit(cursor):
        if cursor == len(data):
            return 0
        choices = [1+length+visit(cursor+length)
                   for length in range(1,min(128,len(data)-cursor)+1)]
        for distance in range(1,min(cursor,65535)+1):
            for length in range(3,min(130,len(data)-cursor)+1):
                if all(data[cursor+k] == data[cursor+k-distance] for k in range(length)):
                    choices.append(3+visit(cursor+length))
        return min(choices)
    return visit(0)


class RawCodecTests(unittest.TestCase):
    def test_all_small_binary_strings_against_independent_oracle(self):
        for size in range(1,9):
            for values in product((65,66),repeat=size):
                source = bytes(values)
                packed,proof = encode(source)
                self.assertEqual(len(packed),oracle(source),source)
                self.assertEqual(decode(packed,size),source)
                self.assertEqual(proof['suffix_cost_bytes'][0],len(packed))
                self.assertEqual(proof['suffix_cost_bytes'][-1],0)

    def test_limits_overlap_and_determinism(self):
        for source in (bytes(range(256)),b'A'*400,(b'ABCD'*100)):
            packed,proof = encode(source)
            self.assertEqual(decode(packed,len(source)),source)
            self.assertEqual(encode(source),(packed,proof))
            self.assertEqual(sum(x['packed_end']-x['packed_start'] for x in proof['path']),len(packed))
        packed,_ = encode(b'A'*131)
        self.assertEqual(packed,b'\x00A\xff\x01\x00')

    def test_tie_prefers_literal(self):
        packed,proof = encode(b'AAAAB')
        # At decoded position1, literal AAAB costs5 and match AAA + literalB costs5.
        self.assertEqual(proof['selected_lengths'][1],4)
        self.assertEqual(proof['selected_distances'][1],0)

    def test_closest_longest_match(self):
        packed,proof = encode(b'ABCABCABCABCABC')
        matches = [x for x in proof['path'] if x['kind']=='match']
        self.assertTrue(matches)
        self.assertEqual(matches[0]['distance'],3)

    def test_malformed_streams(self):
        for packed,size in ((b'',1),(b'\x02AB',3),(b'\x80',3),(b'\x80\x01',3),
                            (b'\x00A\x80\x00\x00',4),
                            (b'\x00A\x80\x02\x00',4),
                            (b'\x00A\xff\x01\x00',130),
                            (b'\x00A',2),(b'\x00A\x00B',1)):
            with self.subTest(packed=packed,size=size),self.assertRaises(ValueError):
                decode(packed,size)

    def test_invalid_inputs(self):
        for source in (b'',bytearray(b'A'),b'A'*524289):
            with self.assertRaises(ValueError):
                encode(source)
        for size in (0,-1,True,1.0,524289):
            with self.assertRaises(ValueError):
                decode(b'\x00A',size)


if __name__ == '__main__':
    unittest.main()
