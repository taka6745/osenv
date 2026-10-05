"""Place project-authored hexadecimal bytes and fixed-width address fields only."""
import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

WIDTH = {'abs16': 2, 'abs32': 4, 'abs64': 8, 'rel8': 1, 'rel16': 2, 'rel32': 4,
         'value16': 2, 'value32': 4}


def place(paths, values=None, contents=None):
    values = values or {}
    symbols, cells, fixes, ranges = {}, {}, [], {}
    section, cursor = 'text', None
    for path in paths:
        source = contents[path] if contents is not None else Path(path).read_text()
        for number, raw in enumerate(source.splitlines(), 1):
            line = raw.split(';', 1)[0].strip()
            if not line:
                continue
            where = f'{path}:{number}'
            if line.startswith('.section '):
                section = line.split()[1]
                if section not in ('text', 'bss'):
                    raise ValueError(f'{where}: unsupported section')
                cursor = None
                continue
            if line.startswith('.org '):
                address = int(line.split()[1], 16)
                if not 0 <= address < 1 << 64:
                    raise ValueError(f'{where}: address outside 64-bit range')
                if cursor is not None and address < cursor:
                    raise ValueError(f'{where}: backward placement')
                cursor = address
                continue
            if cursor is None:
                raise ValueError(f'{where}: address required')
            if line.startswith('@'):
                name = line[1:]
                if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name) or name in symbols:
                    raise ValueError(f'{where}: invalid or duplicate label')
                symbols[name] = (cursor, section)
                continue
            if line.startswith('.zero ') or line.startswith('.align '):
                op, arg = line.split()
                n = int(arg)
                if n < 0 or n > 1048576 or (op == '.align' and (not n or n & (n-1))):
                    raise ValueError(f'{where}: invalid reservation')
                count = n if op == '.zero' else (-cursor) % n
                tokens = ['00'] * count if section == 'text' else []
                if section == 'bss':
                    if cursor+count > 1 << 64:
                        raise ValueError(f'{where}: reservation outside 64-bit range')
                    if any(cursor <= a < cursor+count for a in cells) or any(cursor < end and start < cursor+count for start,end in ranges.get('bss',[]) if count):
                        raise ValueError(f'{where}: overlapping reservation')
                    ranges.setdefault(section, []).append((cursor, cursor+count))
                    cursor += count
                    continue
            else:
                tokens = line.split()
            for token in tokens:
                if section != 'text':
                    raise ValueError(f'{where}: BSS contains bytes')
                if re.fullmatch(r'[0-9a-fA-F]{2}', token):
                    data = bytes.fromhex(token)
                elif ':' in token and token.split(':')[0] in WIDTH:
                    kind, name = token.split(':', 1)
                    fixes.append((cursor, kind, name, where))
                    data = bytes(WIDTH[kind])
                else:
                    raise ValueError(f'{where}: invalid byte or field {token!r}')
                for byte in data:
                    if cursor >= 1 << 64:
                        raise ValueError(f'{where}: byte outside 64-bit range')
                    if cursor in cells or any(start <= cursor < end for start,end in ranges.get('bss',[])):
                        raise ValueError(f'{where}: overlapping bytes')
                    cells[cursor] = byte
                    cursor += 1
    for address, kind, name, where in fixes:
        width = WIDTH[kind]
        if kind.startswith('value'):
            if name not in values:
                raise ValueError(f'{where}: missing build field {name}')
            value = values[name]
        else:
            if name not in symbols:
                raise ValueError(f'{where}: unresolved {name}')
            value = symbols[name][0]
        relative = kind.startswith('rel')
        if relative:
            value -= address + width
        low, high = (-(1 << (width*8-1)), (1 << (width*8-1))-1) if relative else (0, (1 << (width*8))-1)
        if not low <= value <= high:
            raise ValueError(f'{where}: {kind} overflow {value}')
        for i, byte in enumerate(value.to_bytes(width, 'little', signed=relative)):
            cells[address+i] = byte
    return cells, symbols, ranges


def span(cells, start, end):
    if end <= start or end-start > 1048576:
        raise ValueError('invalid image span')
    return bytes(cells.get(i, 0) for i in range(start, end))


def fnv(data):
    value = 2166136261
    for byte in data:
        value = ((value ^ byte) * 16777619) & 0xffffffff
    return value


def elf(data, base, symbols):
    """Write a conventional ELF64 symbol container; executable bytes are unchanged."""
    names = bytearray(b'\0')
    records = bytearray(bytes(24))
    for name, (address, section) in sorted(symbols.items(), key=lambda item: item[1][0]):
        offset = len(names)
        names.extend(name.encode()+b'\0')
        records.extend(struct.pack('<IBBHQQ', offset, 0x10, 0, 1 if section == 'text' else 2, address, 0))
    shnames = b'\0.text\0.bss\0.symtab\0.strtab\0.shstrtab\0'
    output = bytearray(bytes(64))
    textoff = len(output); output.extend(data)
    symoff = len(output); output.extend(records)
    stroff = len(output); output.extend(names)
    shstroff = len(output); output.extend(shnames)
    output.extend(bytes((-len(output)) % 8))
    shoff = len(output)
    sections = [(0,0,0,0,0,0,0,0,0,0),
                (1,1,6,base,textoff,len(data),0,0,1,0),
                (7,8,3,0x180000,0,0x20000,0,0,4096,0),
                (12,2,0,0,symoff,len(records),4,1,8,24),
                (20,3,0,0,stroff,len(names),0,0,1,0),
                (28,3,0,0,shstroff,len(shnames),0,0,1,0)]
    for record in sections:
        output.extend(struct.pack('<IIQQQQIIQQ', *record))
    output[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01'+bytes(9),2,62,1,base,0,shoff,0,64,0,0,64,6,5)
    return output


def packed_payload(kernel, path, source):
    """Optimal authored-format data packing; executable adapter bytes stay literal."""
    from .raw_codec import encode, decode
    compressed, proof = encode(kernel)
    if decode(compressed, len(kernel)) != kernel:
        raise ValueError('packing round trip failed')
    keys = ('blob_source','relocated_bytes','input_start','input_end',
            'decoded_kernel_end','decoded_kernel_size','decoded_kernel_hash')
    _, symbols, _ = place([path],dict.fromkeys(keys,0),contents={path:source})
    stub_size = symbols['packed_stub_end'][0]-0x100000
    decoder_size = symbols['packed_decoder_end'][0]-0x80000
    relocated = decoder_size+len(compressed)
    if not 0 < stub_size <= 512 or not 0 < decoder_size <= 4096 or not 0 < relocated <= 65536:
        raise ValueError('packed adapter outside staging bounds')
    values = {'blob_source':0x100000+stub_size,'relocated_bytes':relocated,
              'input_start':0x80000+decoder_size,'input_end':0x80000+relocated,
              'decoded_kernel_end':0x100000+len(kernel),
              'decoded_kernel_size':len(kernel),'decoded_kernel_hash':fnv(kernel)}
    cells, symbols, _ = place([path],values,contents={path:source})
    if len(cells) != stub_size+decoder_size or any(not (0x80000 <= a < 0x80000+decoder_size or 0x100000 <= a < 0x100000+stub_size) for a in cells):
        raise ValueError('unexpected packed adapter placement')
    stub = span(cells,0x100000,0x100000+stub_size)
    decoder = span(cells,0x80000,0x80000+decoder_size)
    payload = stub+decoder+compressed
    if len(payload) > 0xfe00 or values['input_end'] > 0x90000:
        raise ValueError('packed image outside BIOS/staging bounds')
    metadata = {'format':'authored literal1..128/match3..130/distance16',
                'stub_bytes':stub_size,'decoder_bytes':decoder_size,
                'compressed_bytes':len(compressed),'payload_bytes':len(payload),
                'values':values,'symbols':{n:a for n,(a,s) in symbols.items()},
                'optimal_stream_bytes':proof['optimal_bytes'],
                'codec_sha256':hashlib.sha256(Path(__file__).with_name('raw_codec.py').read_bytes()).hexdigest()}
    return payload, decoder, symbols, metadata, proof


def pvh_elf(segments, kernel, entry):
    """ELF32 load/note container; no executable bytes are generated here."""
    header_size, ph_size, count = 52, 32, len(segments)+2
    if not segments or count > 64:
        raise ValueError('Bounded nonempty PVH segments required')
    note = struct.pack('<III4sI', 4, 4, 18, b'Xen\0', entry)
    note_offset = header_size + ph_size*count
    header = struct.pack('<16sHHIIIIIHHHHHH', b'\x7fELF\x01\x01\x01'+bytes(9),
                         2, 3, 1, entry, header_size, 0, 0, header_size, ph_size, count, 0, 0, 0)
    rows = [(4, note_offset, 0, 0, len(note), len(note), 4, 4)]
    payloads = []
    cursor = note_offset+len(note)
    for base,data in segments+[(0x100000,kernel)]:
        if not data:
            raise ValueError('Empty PVH load segment')
        cursor = (cursor+15)&~15
        rows.append((1,cursor,base,base,len(data),len(data),5,1))
        payloads.append((cursor,data))
        cursor += len(data)
    programs = b''.join(struct.pack('<IIIIIIII', *row) for row in rows)
    output = bytearray(cursor)
    output[:len(header)] = header
    output[header_size:note_offset] = programs
    output[note_offset:note_offset+len(note)] = note
    for start,data in payloads:
        output[start:start+len(data)] = data
    return bytes(output)


def build(project, output, packed=False, pvh=False):
    project, output = Path(project).resolve(), Path(output).resolve()
    if output == project or project in output.parents:
        raise ValueError('generated output must remain outside OS checkout')
    root = project/'src/raw'
    kernel_paths = [root/name for name in ('entry.inc','primitives.inc','driver.inc','network.inc','irq.inc')]
    paths=[root/'boot.inc']+kernel_paths
    if packed:
        paths.append(root/'packed.inc')
    if pvh:
        paths += [root/'pvh.inc', root/'pvh-pci.inc']
    for path in paths:
        if project not in path.resolve().parents:
            raise ValueError('guest source escapes repository')
    sourcebytes={p:p.read_bytes() for p in paths}
    contents={p:b.decode('utf-8') for p,b in sourcebytes.items()}
    cells, symbols, ranges = place(kernel_paths, contents=contents)
    if min(cells) != 0x100000 or max(cells) >= 0x10fe00:
        raise ValueError('kernel outside bounded BIOS loading window')
    if any(start < 0x180000 or end > 0x1a0000 for start,end in ranges.get('bss',[])):
        raise ValueError('BSS outside initialized state window')
    kernel = span(cells, 0x100000, max(cells)+1)
    payload = kernel
    packing = None
    if packed:
        payload, decoder, packed_symbols, packing, proof = packed_payload(kernel,root/'packed.inc',contents[root/'packed.inc'])
    sectors = (len(payload)+511)//512
    bootcells, bootsymbols, _ = place([root/'boot.inc'], {'kernel_size':len(payload), 'kernel_sectors':sectors, 'kernel_hash':fnv(payload)}, contents=contents)
    if min(bootcells) != 0x7c00 or max(bootcells) != 0x7dff:
        raise ValueError('boot sector must occupy exactly512 bytes')
    boot = span(bootcells,0x7c00,0x7e00)
    if boot[-2:] != b'\x55\xaa':
        raise ValueError('missing boot signature')
    output.mkdir(parents=True,exist_ok=False)
    for path, data in sourcebytes.items():
        saved=output/'sources'/path.relative_to(project)
        saved.parent.mkdir(parents=True,exist_ok=True)
        saved.write_bytes(data)
    (output/'kernel.bin').write_bytes(kernel)
    (output/'kernel.elf').write_bytes(elf(kernel,0x100000,symbols))
    (output/'boot.elf').write_bytes(elf(boot,0x7c00,bootsymbols))
    image=boot+payload+bytes((-len(payload))%512)
    (output/'oslab.img').write_bytes(image)
    report={'route':'hand-placed hexadecimal bytes; no compiler/assembler/linker', 'kernel_bytes':len(kernel),'image_bytes':len(image),'padding_bytes':len(kernel)-len(cells), 'image_sha256':hashlib.sha256(image).hexdigest(),'sources':{str(p.relative_to(project)):hashlib.sha256(sourcebytes[p]).hexdigest() for p in paths},'symbols':{n:a for n,(a,s) in symbols.items()},'boot_symbols':{n:a for n,(a,s) in bootsymbols.items()},'bss':ranges,'cpu_modes':{'boot16':[0x7c00,bootsymbols['boot_protected'][0]],'boot32':[bootsymbols['boot_protected'][0],0x7e00],'kernel32':[0x100000,symbols['raw_entry'][0]],'kernel64':[symbols['raw_entry'][0],max(cells)+1]},'writer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'python_version':sys.version}
    if packed:
        report['packing'] = packing
        report['cpu_modes'].update({'packed_stub32':[0x100000,0x100000+packing['stub_bytes']], 'packed_decode32':[0x80000,0x80000+packing['decoder_bytes']]})
        (output/'packed.bin').write_bytes(payload)
        (output/'packed.elf').write_bytes(elf(decoder,0x80000,{n:v for n,v in packed_symbols.items() if 0x80000 <= v[0] <= 0x80000+len(decoder)}))
        (output/'packed-stub.elf').write_bytes(elf(payload[:packing['stub_bytes']],0x100000,{n:v for n,v in packed_symbols.items() if v[0] >= 0x100000}))
        (output/'packing-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
    (output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    if pvh:
        direct_paths = [root/'pvh.inc', root/'pvh-pci.inc']
        combined, all_symbols, direct_ranges = place(kernel_paths+direct_paths,
            {'kernel_size':len(kernel), 'kernel_hash':fnv(kernel)}, contents=contents)
        direct_symbols = {name:value for name,value in all_symbols.items()
                          if value[1] == 'text' and 0x110000 <= value[0] < 0x180000}
        base = direct_symbols['raw_pvh_entry'][0]
        direct_cells = {a:b for a,b in combined.items() if a >= base}
        if direct_ranges != ranges or min(direct_cells) != base or not 0x110000 <= base <= max(direct_cells) < 0x180000:
            raise ValueError('PVH adapter outside verified low usable RAM, or overlaps kernel/state')
        if span(combined, 0x100000, max(cells)+1) != kernel:
            raise ValueError('PVH source changed the existing kernel bytes')
        adapter = span(direct_cells, base, max(direct_cells)+1)
        entry = direct_symbols['raw_pvh_entry'][0]
        segments = []
        for address in sorted(direct_cells):
            if not segments or address != segments[-1][0]+len(segments[-1][1]):
                segments.append((address, bytearray()))
            segments[-1][1].append(direct_cells[address])
        loader = pvh_elf(segments, kernel, entry)
        (output/'pvh.elf').write_bytes(loader)
        (output/'pvh-symbols.elf').write_bytes(elf(adapter, base, direct_symbols))
        provenance = {'route':'authored literal PHYS32 entry; complete kernel embedded; no guest compiler',
                      'preload':False, 'sources':report['sources'],
                      'generated_artifacts':{name:hashlib.sha256((output/name).read_bytes()).hexdigest()
                                            for name in ('pvh.elf','oslab.img','kernel.elf','kernel.bin')},
                      'symbols':{name:address for name,(address,_) in direct_symbols.items()},
                      'adapter_bytes':len(direct_cells),'adapter_span_bytes':len(adapter),
                      'cpu_modes':{'pvh32':[base,max(direct_cells)+1]}}
        (output/'pvh-inputs.json').write_text(json.dumps(provenance,indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--packed',action='store_true')
    parser.add_argument('--pvh',action='store_true')
    args=parser.parse_args()
    print(json.dumps(build(args.project,args.output,args.packed,args.pvh),indent=2))
