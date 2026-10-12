"""Fail-closed discovery tests using self-authored, non-executed PE fixtures."""
import struct
import unittest

from locator import discover_bytes, UnsupportedImplementation


def fixture(output='rbx', duplicate=False, stride=28, result_offset=24, broken_call=False, image_base=0x140000000, leaf_codec_offset=12):
    # Build only the semantic contract needed by the static inspector.
    base = 3 if output == 'rbx' else 6
    code = bytearray.fromhex('53 48 83 ec 30')
    code += bytes.fromhex('48 8b') + bytes([0xda if output == 'rbx' else 0xf2])
    code += bytes.fromhex('45 8b d0 41 0f b6 c1 83 f8 05 7d 00 7d 00')
    call = len(code)
    code += b'\xe8' + struct.pack('<i', (0x1700 if broken_call else 0x1300) - (0x1000+call+5))
    for value in [bytes.fromhex('44 89') + bytes([0x40+base, result_offset]),
                  bytes.fromhex('89') + bytes([0x50+base, result_offset])]:
        code += bytes.fromhex('0f 10 44 24 20 0f 11') + bytes([base])
        code += bytes.fromhex('f2 0f 10 4c 24 30 f2 0f 11') + bytes([0x48+base, 16])
        code += value
    code += bytes.fromhex('48 c7') + bytes([base]) + struct.pack('<I', 1)
    code += bytes.fromhex('c6') + bytes([0x40+base, 8, 0])
    code += bytes.fromhex('48 c7') + bytes([0x40+base, 12]) + struct.pack('<I', 2)
    code += bytes.fromhex('c7') + bytes([0x40+base, result_offset]) + struct.pack('<I', 0xfffffffd)
    code += b'\x90' * 32
    code += bytes.fromhex('48 8b') + bytes([0xc0+base]) + bytes.fromhex('48 83 c4 30 5b c3')
    leaf = bytearray.fromhex('4c 8b 59 38 48 8b 41 30 83 f9 01 83 f9 02')
    for target in [1, 2]:
        for offset in [0, 4, 8, leaf_codec_offset, 16, 20, 24]:
            if offset == 0:
                leaf += bytes.fromhex('8b 08 41 89') + bytes([0x08+target])
            elif offset == 8:
                leaf += bytes.fromhex('0f b6 48 08 41 88') + bytes([0x48+target, offset])
            else:
                leaf += bytes.fromhex('8b 48') + bytes([offset])
                leaf += bytes.fromhex('41 89') + bytes([0x48+target, offset])
    leaf += bytes.fromhex('48 83 c0') + bytes([stride]) + b'\xc3'
    text = bytearray(b'\xcc' * 0x800)
    text[:len(code)] = code
    text[0x300:0x305] = b'\xe9' + struct.pack('<i', 0x1400-0x1305)
    text[0x400:0x400+len(leaf)] = leaf
    pdata = struct.pack('<III', 0x1000, 0x1000+len(code), 0)
    if duplicate:
        second = bytearray(code)
        second[call+1:call+5] = struct.pack('<i', 0x1300-(0x1600+call+5))
        text[0x600:0x600+len(second)] = second
        pdata += struct.pack('<III', 0x1600, 0x1600+len(code), 0)
    data = bytearray(0xe00)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664, 3, 0, 0, 0, 240, 0x22)
    optional = 0x98
    struct.pack_into('<H', data, optional, 0x20b)
    struct.pack_into('<I', data, optional+16, 0x1000)
    struct.pack_into('<Q', data, optional+24, image_base)
    struct.pack_into('<II', data, optional+32, 0x1000, 0x200)
    struct.pack_into('<II', data, optional+56, 0x5000, 0x200)
    struct.pack_into('<I', data, optional+108, 16)
    struct.pack_into('<II', data, optional+112+3*8, 0x4000, len(pdata))
    sections = [(b'.text', 0x1000, 0x800, 0x200, 0x60000020),
                (b'.rdata', 0x3000, 0x200, 0xa00, 0x40000040),
                (b'.pdata', 0x4000, 0x200, 0xc00, 0x40000040)]
    for i, (name, rva, size, raw, flags) in enumerate(sections):
        struct.pack_into('<8sIIIIIIHHI', data, optional+240+i*40, name, size, rva, size, raw, 0, 0, 0, 0, flags)
    data[0x200:0xa00] = text
    schema = b'VideoQuality_Bluray\x10\x04\0CodecType_H264\x10\x01\0CodecType_H265\x10\x02'
    data[0xa00:0xa00+len(schema)] = schema
    data[0xc00:0xc00+len(pdata)] = pdata
    return bytes(data)


class DiscoveryTests(unittest.TestCase):
    def test_register_variants_and_leaf_without_unwind_metadata(self):
        for output in ['rbx', 'rsi']:
            with self.subTest(output=output):
                profile = discover_bytes(fixture(output=output))
                self.assertEqual(profile.matcher.rva, 0x1000)
                self.assertIsNone(profile.presenter)

    def test_image_base_does_not_determine_location(self):
        first = discover_bytes(fixture())
        second = discover_bytes(fixture(image_base=0x180000000))
        self.assertEqual(first.matcher, second.matcher)
        self.assertNotEqual(first.sha256, second.sha256)

    def test_ambiguous_matches_are_rejected(self):
        with self.assertRaisesRegex(UnsupportedImplementation, 'found 2'):
            discover_bytes(fixture(duplicate=True))

    def test_changed_record_stride_is_rejected(self):
        with self.assertRaisesRegex(UnsupportedImplementation, 'found 0'):
            discover_bytes(fixture(stride=32))

    def test_changed_result_layout_is_rejected(self):
        with self.assertRaisesRegex(UnsupportedImplementation, 'found 0'):
            discover_bytes(fixture(result_offset=28))

    def test_unrelated_callee_is_rejected(self):
        with self.assertRaisesRegex(UnsupportedImplementation, 'found 0'):
            discover_bytes(fixture(broken_call=True))

    def test_changed_codec_field_is_rejected(self):
        with self.assertRaisesRegex(UnsupportedImplementation, 'found 0'):
            discover_bytes(fixture(leaf_codec_offset=28))

    def test_changed_quality_enum_is_rejected(self):
        data = fixture().replace(b'VideoQuality_Bluray\x10\x04', b'VideoQuality_Bluray\x10\x07')
        with self.assertRaisesRegex(UnsupportedImplementation, 'enum'):
            discover_bytes(data)

    def test_wrong_architecture_is_rejected(self):
        data = bytearray(fixture())
        struct.pack_into('<H', data, 0x84, 0x14c)
        with self.assertRaisesRegex(UnsupportedImplementation, 'x64'):
            discover_bytes(bytes(data))

    def test_invalid_file_is_rejected(self):
        with self.assertRaises(UnsupportedImplementation):
            discover_bytes(b'not an executable')


if __name__ == '__main__':
    unittest.main()
