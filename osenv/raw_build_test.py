"""Exercise byte-placement safety; these tests provide no guest implementations."""
import tempfile
import unittest
import struct
from pathlib import Path
from .raw_build import place, fnv, elf, build, pvh_elf


class RawPlacementTests(unittest.TestCase):
    def run_source(self, source, values=None):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'bytes.inc'
            path.write_text(source)
            return place([path], values)

    def test_literal_and_relative(self):
        cells,symbols,_=self.run_source('.org 1000\n@start\nEB rel8:done\n00\n@done\nC3\n')
        self.assertEqual(bytes(cells[x] for x in sorted(cells)), b'\xeb\x01\0\xc3')
        self.assertEqual(symbols['done'][0],0x1003)

    def test_negative_branch(self):
        cells,_,_=self.run_source('.org 1000\n@start\n90 EB rel8:start\n')
        self.assertEqual(cells[0x1002],253)

    def test_signed_branch_endpoints(self):
        for gap in (127,128):
            source=f'.org 1000\nEB rel8:end\n.zero {gap}\n@end\nC3\n'
            if gap==127:
                self.assertEqual(self.run_source(source)[0][0x1001],127)
            else:
                with self.assertRaisesRegex(ValueError,'overflow'):
                    self.run_source(source)

    def test_duplicate_unknown_overlap_and_mnemonic_rejected(self):
        for source in ('.org 1000\n@x\n@x\n', '.org 1000\nE8 rel32:missing',
                       '.org 1000\n90\n.org 1000\n90', '.org 1000\nmov eax,1'):
            with self.assertRaises(ValueError):
                self.run_source(source)

    def test_bss_emits_no_disk_bytes(self):
        cells,symbols,ranges=self.run_source('.org 1000\n90\n.section bss\n.org 180000\n@state\n.zero 4096\n')
        self.assertEqual(cells,{0x1000:0x90})
        self.assertEqual(symbols['state'],(0x180000,'bss'))
        self.assertEqual(ranges['bss'],[(0x180000,0x181000)])

    def test_build_field_bounds(self):
        with self.assertRaisesRegex(ValueError,'overflow'):
            self.run_source('.org 1000\nvalue16:count',{'count':65536})
        with self.assertRaisesRegex(ValueError,'missing build'):
            self.run_source('.org 1000\nvalue16:count')

    def test_bss_overlap_and_address_bounds(self):
        for source in (
            '.org 1000\n90\n.section bss\n.org 1000\n.zero 1',
            '.section bss\n.org 1000\n.zero 1\n.section text\n.org 1000\n90',
            '.section bss\n.org 180000\n.zero 16\n.section bss\n.org 180000\n.zero 16',
            '.section bss\n.org -1\n.zero 1',
            '.section bss\n.org ffffffffffffffff\n.zero 2',
            '.org ffffffffffffffff\n90 90',
        ):
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.run_source(source)
        cells,_,ranges=self.run_source('.section bss\n.org 1000\n.zero 1\n.zero 1\n.section text\n.org 1002\n90')
        self.assertEqual(cells,{0x1002:0x90})
        self.assertEqual(ranges['bss'],[(0x1000,0x1001),(0x1001,0x1002)])

    def test_elf_preserves_actual_bytes(self):
        data=b'\x90\xc3'
        container=elf(data,0x100000,{'entry':(0x100000,'text')})
        self.assertEqual(container[:4],b'\x7fELF')
        self.assertEqual(container[64:66],data)
        self.assertEqual(fnv(b''),2166136261)

    def test_build_rejects_uninitialized_state(self):
        with tempfile.TemporaryDirectory() as directory:
            project=Path(directory)/'project'
            sources=project/'src/raw'
            sources.mkdir(parents=True)
            for name in ('entry.inc','primitives.inc','driver.inc','network.inc','irq.inc','boot.inc'):
                (sources/name).write_text('')
            (sources/'entry.inc').write_text('.org 100000\n90\n.section bss\n.org 1a0000\n.zero 1')
            with self.assertRaisesRegex(ValueError,'initialized state'):
                build(project,Path(directory)/'output')
            self.assertFalse((Path(directory)/'output').exists())

    def test_pvh_segments_preserve_literal_data_without_holes(self):
        # Data-only container test: no executable adapter or OS is simulated.
        segments = [(0x110000,b'abc'),(0x111000,b'defg')]
        raw = pvh_elf(segments,b'kernel',0x110000)
        self.assertEqual(raw[:7],b'\x7fELF\x01\x01\x01')
        self.assertEqual(struct.unpack_from('<I',raw,24)[0],0x110000)
        offset=struct.unpack_from('<I',raw,28)[0]
        count=struct.unpack_from('<H',raw,44)[0]
        self.assertEqual(count,4)
        loads=[]
        for i in range(count):
            kind,start,va,pa,length,memory,flags,alignment=struct.unpack_from('<IIIIIIII',raw,offset+32*i)
            self.assertLessEqual(start+length,len(raw))
            if kind==1:
                self.assertEqual(length,memory)
                self.assertEqual(va,pa)
                loads.append((pa,raw[start:start+length]))
            else:
                self.assertEqual(raw[start:start+length],struct.pack('<III4sI',4,4,18,b'Xen\0',0x110000))
        self.assertEqual(loads,segments+[(0x100000,b'kernel')])
        self.assertLess(len(raw),512)
        with self.assertRaises(ValueError):pvh_elf([],b'kernel',0x110000)


if __name__=='__main__':
    unittest.main()
