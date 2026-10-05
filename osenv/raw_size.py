"""Exact source-derived storage accounting for immutable raw OS builds.

This is accounting, not an optimizer or a proof of shortest equivalent programs.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from .raw_build import WIDTH, place, span, fnv


def sha(data):
    return hashlib.sha256(data).hexdigest()


def provenance(paths):
    """Map each emitted byte to its directive/token, without decoding instructions."""
    cells, reservations = {}, []
    section, cursor, label = 'text', None, None
    for path in paths:
        for number, raw in enumerate(path.read_text().splitlines(), 1):
            line = raw.split(';', 1)[0].strip()
            if not line:
                continue
            if line.startswith('.section '):
                section, cursor = line.split()[1], None
                continue
            if line.startswith('.org '):
                cursor = int(line.split()[1], 16)
                continue
            if line.startswith('@'):
                label = line[1:]
                continue
            base = {'source': str(path), 'line': number, 'label': label}
            if line.startswith(('.zero ', '.align ')):
                op, arg = line.split()
                count = int(arg) if op == '.zero' else (-cursor) % int(arg)
                kind = 'explicit_zero' if op == '.zero' else 'alignment'
                if section == 'bss':
                    reservations.append(dict(base, start=cursor, end=cursor+count, bytes=count))
                else:
                    for address in range(cursor, cursor+count):
                        cells[address] = dict(base, kind=kind)
                cursor += count
                continue
            for token in line.split():
                kind = 'fixup' if ':' in token else 'literal'
                width = WIDTH[token.split(':')[0]] if kind == 'fixup' else 1
                for address in range(cursor, cursor+width):
                    cells[address] = dict(base, kind=kind, token=token)
                cursor += width
    return cells, reservations


def runs(rows):
    result = []
    for offset, row in enumerate(rows):
        if result and result[-1]['provenance'] == row:
            result[-1]['end'] += 1
        else:
            result.append({'start': offset, 'end': offset+1, 'provenance': row})
    return result


def packed_account(build, root, kernel, metadata):
    """Reconstruct adapter and certify stream independently of writer metadata."""
    from .raw_codec import encode, decode
    path = root/'packed.inc'
    keys = ('blob_source','relocated_bytes','input_start','input_end',
            'decoded_kernel_end','decoded_kernel_size','decoded_kernel_hash')
    _, symbols, _ = place([path], dict.fromkeys(keys,0))
    stub_size = symbols['packed_stub_end'][0]-0x100000
    decoder_size = symbols['packed_decoder_end'][0]-0x80000
    compressed, proof = encode(kernel)
    saved_proof = json.loads((build/'packing-proof.json').read_text())
    if proof != saved_proof:
        raise ValueError('packing optimality certificate mismatch')
    relocated = decoder_size+len(compressed)
    values = {'blob_source':0x100000+stub_size,'relocated_bytes':relocated,
              'input_start':0x80000+decoder_size,'input_end':0x80000+relocated,
              'decoded_kernel_end':0x100000+len(kernel),
              'decoded_kernel_size':len(kernel),'decoded_kernel_hash':fnv(kernel)}
    cells, symbols, _ = place([path],values)
    if len(cells) != stub_size+decoder_size:
        raise ValueError('packed adapter has unexpected holes or cells')
    payload = span(cells,0x100000,0x100000+stub_size)+span(cells,0x80000,0x80000+decoder_size)+compressed
    actual = (build/'packed.bin').read_bytes()
    actual_stream = actual[stub_size+decoder_size:]
    if decode(actual_stream,len(kernel)) != kernel or actual_stream != compressed or actual != payload:
        raise ValueError('packed stream or adapter reconstruction mismatch')
    expected = {'format':'authored literal1..128/match3..130/distance16',
                'stub_bytes':stub_size,'decoder_bytes':decoder_size,
                'compressed_bytes':len(compressed),'payload_bytes':len(payload),
                'values':values,'symbols':{n:a for n,(a,section) in symbols.items()},
                'optimal_stream_bytes':proof['optimal_bytes']}
    if {k:v for k,v in metadata.items() if k != 'codec_sha256'} != expected:
        raise ValueError('packing manifest mismatch')
    source_rows, _ = provenance([path])
    rows = []
    for start,size in ((0x100000,stub_size),(0x80000,decoder_size)):
        for address in range(start,start+size):
            row = dict(source_rows[address])
            row['source'] = 'src/raw/packed.inc'
            row['kind'] = 'adapter_'+row['kind']
            rows.append(row)
    for token in proof['path']:
        base = {'decoded_start':token['source_start'],'decoded_end':token['source_end'],
                'distance':token['distance'],'codec':'literal128/backref130-distance16'}
        rows.append(dict(base,kind='compressed_tag'))
        if token['kind'] == 'match':
            rows.extend([dict(base,kind='compressed_distance') for _ in range(2)])
        else:
            for offset in range(token['source_start'],token['source_end']):
                rows.append(dict(base,kind='compressed_literal',decoded_byte=offset))
    if len(rows) != len(payload):
        raise ValueError('packed provenance conservation failed')
    return payload, rows, proof, expected


def account(build):
    build = Path(build).resolve()
    manifest = json.loads((build/'manifest.json').read_text())
    names = ['entry.inc', 'primitives.inc', 'driver.inc', 'network.inc', 'irq.inc']
    root = build/'sources/src/raw'
    paths = [root/name for name in names]
    bootpath = root/'boot.inc'
    for name, digest in manifest['sources'].items():
        if Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('unsafe source path')
        if sha((build/'sources'/name).read_bytes()) != digest:
            raise ValueError('source hash mismatch: '+name)
    kernelcells, symbols, bss = place(paths)
    kernel = span(kernelcells, 0x100000, max(kernelcells)+1)
    if manifest['padding_bytes'] != len(kernel)-len(kernelcells):
        raise ValueError('manifest kernel placement padding mismatch')
    payload, packed_rows, packing_proof, packing_metadata = kernel, None, None, None
    if 'packing' in manifest:
        payload, packed_rows, packing_proof, packing_metadata = packed_account(build,root,kernel,manifest['packing'])
    bootcells, bootsymbols, _ = place([bootpath], {'kernel_size':len(payload), 'kernel_sectors':(len(payload)+511)//512, 'kernel_hash':fnv(payload)})
    boot = span(bootcells, 0x7c00, 0x7e00)
    image = boot+payload+bytes((-len(payload))%512)
    if boot[-2:] != b'\x55\xaa' or image != (build/'oslab.img').read_bytes() or kernel != (build/'kernel.bin').read_bytes():
        raise ValueError('image differs from source reconstruction')
    if sha(image) != manifest['image_sha256'] or len(image) != manifest['image_bytes'] or len(kernel) != manifest['kernel_bytes']:
        raise ValueError('manifest image mismatch')
    if {n:a for n,(a,s) in symbols.items()} != manifest['symbols'] or {n:a for n,(a,s) in bootsymbols.items()} != manifest['boot_symbols'] or {k:[list(x) for x in v] for k,v in bss.items()} != manifest['bss']:
        raise ValueError('manifest symbols/reservations mismatch')
    metadata, reservations = provenance([bootpath]+paths)
    for row in list(metadata.values())+reservations:
        row['source'] = str(Path(row['source']).relative_to(build/'sources'))
    rows = []
    for offset in range(len(image)):
        address = 0x7c00+offset if offset < 512 else 0x100000+offset-512
        if offset >= 512+len(payload):
            row = {'kind':'sector_fill'}
        elif packed_rows is not None and offset >= 512:
            row = packed_rows[offset-512]
        else:
            row = metadata.get(address, {'kind':'placement_hole', 'stage':'boot' if offset < 512 else 'kernel'})
        rows.append(row)
    counts = Counter(row['kind'] for row in rows)
    modules = {}
    for row in rows:
        if 'source' in row:
            modules.setdefault(row['source'], Counter())[row['kind']] += 1
    body_start = symbols['http_response_3'][0]-0x100000
    response = kernel[body_start:]
    header, body = response.split(b'\r\n\r\n',1)
    length = int(next(line.split(b':',1)[1] for line in header.split(b'\r\n') if line.lower().startswith(b'content-length:')))
    body = body[:length]
    if len(body) != length:
        raise ValueError('truncated literal HTTP body')
    authored = counts['literal']+counts['fixup']+counts['explicit_zero']
    boot_authored = sum(row['kind'] in ('literal','fixup','explicit_zero') for row in rows[:512])
    kernel_authored = authored-boot_authored
    lower_disk = 512+((kernel_authored+511)//512)*512
    result = {'schema':1, 'image_sha256':sha(image), 'sources':manifest['sources'], 'accountant_sha256':sha(Path(__file__).read_bytes()),
              'image_bytes':len(image), 'image_bits':8*len(image), 'kernel_bytes':len(kernel), 'kernel_bits':8*len(kernel),
              'categories':{k:{'bytes':v,'bits':8*v} for k,v in sorted(counts.items())},
              'modules':{k:dict(v) for k,v in modules.items()}, 'bss_reservations':reservations,
              'bss_reserved_bytes':sum(x['bytes'] for x in reservations), 'bss_disk_bits':0,
              'literal_page':{'bytes':length,'bits':8*length,'sha256':sha(body)},
              'bounds':{'fixed_layout_exact_bits':8*len(image), 'fixed_encoding_nonpadding_bytes':authored,
                        'fixed_encoding_kernel_nonpadding_bytes':kernel_authored,
                        'relocation_only_disk_lower_bound_bytes':lower_disk, 'relocation_only_disk_lower_bound_bits':8*lower_disk,
                        'uncompressed_literal_page_lower_bound_bits':8*length,
                        'bios_sector_minimum_bits':4096, 'bios_signature_bits':16,
                        'minimum_proved_in_constrained_family':lower_disk == len(image),
                        'scope':'Fixed existing literal bytes and field widths, separate 512-byte BIOS sector and sector-rounded kernel. Removing holes/alignment may require relocations and may be infeasible; lower bound is not an accepted executable candidate. Fixed layout has no choices and equals exact reconstruction. Literal page bound assumes unchanged uncompressed storage. No global shortest-program or semantic minimum proof.'},
              'coverage':{'covered_bytes':len(rows),'unclassified_bytes':0}, 'provenance_runs':runs(rows)}
    if packing_proof is not None:
        minimum = 512+((packing_proof['optimal_bytes']+packing_metadata['stub_bytes']+packing_metadata['decoder_bytes']+511)//512)*512
        result['packing'] = packing_metadata
        result['packing_certificate_sha256'] = sha((build/'packing-proof.json').read_bytes())
        result['decoded_kernel_disk_bits'] = 0
        decoded_rows = [metadata.get(0x100000+i,{'kind':'placement_hole','stage':'decoded_kernel'}) for i in range(len(kernel))]
        result['decoded_kernel_provenance_runs'] = runs(decoded_rows)
        result['decoded_kernel_sha256'] = sha(kernel)
        result['decoded_layout_categories'] = dict(Counter(row['kind'] for row in decoded_rows))
        result['literal_page']['stored_uncompressed'] = False
        result['bounds'] = {'fixed_layout_exact_bits':8*len(image),
                            'codec_stream_minimum_bytes':packing_proof['optimal_bytes'],
                            'codec_stream_minimum_bits':packing_proof['optimal_bits'],
                            'fixed_adapter_bytes':packing_metadata['stub_bytes']+packing_metadata['decoder_bytes'],
                            'packed_disk_minimum_bytes':minimum,'packed_disk_minimum_bits':8*minimum,
                            'minimum_proved_in_constrained_family':minimum == len(image),
                            'bios_sector_minimum_bits':4096,'bios_signature_bits':16,
                            'scope':'Exact minimum among streams in the authored literal128/backref130-distance16 grammar for this fixed decoded kernel, plus this fixed adapter and separate 512-byte BIOS sector with sector rounding. All DP suffix costs, deterministic path and emitted bytes were recomputed and matched to the saved certificate. Existing image attains the bound. Other codecs, kernel changes and adapter changes are outside this proof; no global shortest-program claim. The decoded HTML page is compressed and its original length is not a disk lower bound.'}
    if sum(x['bytes'] for x in result['categories'].values()) != len(image):
        raise ValueError('accounting conservation failed')
    if 'src/raw/pvh.inc' in manifest['sources']:
        from .raw_build import pvh_elf, elf
        combined, all_symbols, direct_ranges = place(paths+[root/'pvh.inc',root/'pvh-pci.inc'],
                                                   {'kernel_size':len(kernel),'kernel_hash':fnv(kernel)})
        direct_symbols = {name:value for name,value in all_symbols.items()
                          if value[1]=='text' and 0x110000 <= value[0] < 0x180000}
        base = direct_symbols['raw_pvh_entry'][0]
        direct_cells = {a:b for a,b in combined.items() if a>=base}
        if direct_ranges != bss or span(combined,0x100000,max(kernelcells)+1) != kernel:
            raise ValueError('Direct entry changes existing kernel or reservations')
        segments=[]
        for address in sorted(direct_cells):
            if not segments or address != segments[-1][0]+len(segments[-1][1]):
                segments.append((address,bytearray()))
            segments[-1][1].append(direct_cells[address])
        loader=pvh_elf(segments,kernel,base)
        adapter=span(direct_cells,base,max(direct_cells)+1)
        if ((build/'pvh.elf').read_bytes()!=loader or
            (build/'pvh-symbols.elf').read_bytes()!=elf(adapter,base,direct_symbols)):
            raise ValueError('Direct entry loader/symbol bytes differ from authored source')
        direct_record=json.loads((build/'pvh-inputs.json').read_text())
        if (direct_record['sources'] != manifest['sources'] or direct_record['preload'] is not False
            or direct_record['symbols'] != {n:a for n,(a,s) in direct_symbols.items()}
            or direct_record['adapter_bytes'] != len(direct_cells)
            or direct_record['adapter_span_bytes'] != len(adapter)):
            raise ValueError('Direct entry provenance mismatch')
        for name in ('pvh.elf','oslab.img','kernel.elf','kernel.bin'):
            if direct_record['generated_artifacts'].get(name) != sha((build/name).read_bytes()):
                raise ValueError('Direct entry artifact hash mismatch')
        result['direct_entry']={'loader_bytes':len(loader),'adapter_instruction_data_bytes':len(direct_cells),
                                'loader_sha256':sha(loader),'scope':'Optional separate ELF load container; not counted in BIOS disk minimum'}
    return result


def report(result):
    lines = ['# Raw image storage accounting', '', f"Image: {result['image_bytes']} bytes / {result['image_bits']} bits.", f"SHA-256: `{result['image_sha256']}`", '', '| Storage class | Bytes | Bits |', '|---|---:|---:|']
    for key, value in result['categories'].items():
        lines.append(f"| {key} | {value['bytes']} | {value['bits']} |")
    bound = result['bounds']
    minimum = bound.get('packed_disk_minimum_bytes',bound.get('relocation_only_disk_lower_bound_bytes'))
    attainment = ('The existing reconstructed image attains this bound, proving a minimum only within the stated constrained family.'
                  if bound['minimum_proved_in_constrained_family'] else
                  'This lower bound is not attained; feasibility after relocation is unproved.')
    lines += ['', f"BSS reservations: {result['bss_reserved_bytes']} RAM bytes, zero disk bits. This does not count all implicit stack/page-table/DMA working RAM.", '', result['bounds']['scope'], '', f"Constrained disk lower bound: {minimum} bytes / {8*minimum} bits. {attainment}", '', 'Literal tokens include both instructions and data. The byte grammar has no opcode/data type declarations; classifying them as instructions would be unsupported. Fixups are counted as stored bytes, not additional overhead. Alignment and placement holes are candidates for investigation; no live code or safety check is declared redundant. ELF containers and this report are host metadata and contribute zero guest disk bits.', '', 'Every disk byte has an exclusive provenance interval in accounting.json. All source hashes, image bytes, build fields, symbols and BSS reservations were independently reconstructed and checked.']
    return '\n'.join(lines)+'\n'


def write_accounting(build, output):
    result = account(build)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    (output/'accounting.json').write_text(json.dumps(result, indent=2)+'\n')
    (output/'report.md').write_text(report(result))
    return {'ok':True, 'image_bytes':result['image_bytes'], 'image_bits':result['image_bits'],
            'image_sha256':result['image_sha256'], 'bounds':result['bounds'],
            'accounting':str(output/'accounting.json'), 'report':str(output/'report.md')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    print(json.dumps(write_accounting(args.build,args.output), indent=2))


if __name__ == '__main__':
    main()
