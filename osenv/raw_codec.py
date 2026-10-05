"""Host-only optimal encoder for oslab's authored boot/pack.c token format.

Independent Python implementation from the project's documented literal and
back-reference grammar; no guest instructions or external implementation copied.
Optimality is confined to this codec grammar for a fixed decoded byte sequence.
"""
from bisect import bisect_left
import hashlib

MAX_INPUT = 524288


def _length(value):
    if type(value) is not int or not 1 <= value <= MAX_INPUT:
        raise ValueError('decoded length must be 1..524288')


def _longest(data, cursor, positions):
    maximum = min(130,len(data)-cursor)
    best, best_offset = 0, 0
    prior = positions[data[cursor]]
    end = bisect_left(prior,cursor)
    for index in range(end-1,-1,-1):
        offset = cursor-prior[index]
        if offset > 65535:
            break
        length = 1
        while length < maximum and data[cursor+length] == data[cursor+length-offset]:
            length += 1
        if length > best:
            best, best_offset = length, offset
        if best == maximum:
            break
    return best, best_offset


def encode(data):
    """Return minimal token stream plus an exact suffix-cost/path certificate.

    Every literal length and every match length through the longest valid match
    is considered. One offset attaining the longest match also witnesses every
    shorter match. Future matches depend solely on the decoded source prefix,
    not how that prefix was encoded, so optimal suffix DP covers every parse.
    Equal costs retain literals; equal longest matches retain closest offsets.
    """
    if not isinstance(data, bytes):
        raise ValueError('source must be bytes')
    size = len(data)
    _length(size)
    positions = [[] for _ in range(256)]
    for cursor,byte in enumerate(data):
        positions[byte].append(cursor)
    costs, lengths, offsets = [0]*(size+1), [0]*size, [0]*size
    for cursor in range(size-1,-1,-1):
        best_cost, best_length, best_offset = size*2+1, 0, 0
        for length in range(1,min(128,size-cursor)+1):
            candidate = 1+length+costs[cursor+length]
            if candidate < best_cost:
                best_cost, best_length = candidate, length
        longest, offset = _longest(data,cursor,positions)
        for length in range(3,longest+1):
            candidate = 3+costs[cursor+length]
            if candidate < best_cost:
                best_cost, best_length, best_offset = candidate, length, offset
        costs[cursor], lengths[cursor], offsets[cursor] = best_cost, best_length, best_offset
    packed, path, cursor = bytearray(), [], 0
    while cursor < size:
        length, offset = lengths[cursor], offsets[cursor]
        packed_start = len(packed)
        if offset:
            packed.append(128 | (length-3))
            packed.extend(offset.to_bytes(2,'little'))
        else:
            packed.append(length-1)
            packed.extend(data[cursor:cursor+length])
        path.append({'source_start':cursor,'source_end':cursor+length,
                     'packed_start':packed_start,'packed_end':len(packed),
                     'kind':'match' if offset else 'literal','distance':offset})
        cursor += length
    packed = bytes(packed)
    if len(packed) != costs[0] or decode(packed,size) != data:
        raise ValueError('encoder consistency failure')
    proof = {'schema':1,'codec':'oslab literal128/backref130-distance16-v1',
             'source_bytes':size,'source_sha256':hashlib.sha256(data).hexdigest(),
             'packed_sha256':hashlib.sha256(packed).hexdigest(),
             'optimal_bytes':costs[0],'optimal_bits':8*costs[0],
             'suffix_cost_bytes':costs,'selected_lengths':lengths,'selected_distances':offsets,'path':path,
             'proof_scope':'Minimum bytes among all valid streams in this grammar decoding to this exact source. Source-position transitions enumerate literal lengths1..128 and match lengths3..130 with valid distances1..65535 including overlap. Cost(size)=0; Cost(i)=min(tokenbytes+Cost(i+decodedlength)). Longest valid offset witnesses all shorter match lengths. Backward induction proves global parse optimality; emitted path attains Cost(0). No claim of shortest executable or other codec minimum.',
             'provenance':'Independent host Python algorithm authored from this repository boot/pack.c format and boot/stage2.asm decoding contract; no external guest code imported.'}
    return packed, proof


def decode(packed, expected_size):
    """Decode with exact source/output bounds, rejecting every malformed token."""
    _length(expected_size)
    if not isinstance(packed,bytes):
        raise ValueError('packed stream must be bytes')
    output, cursor = bytearray(), 0
    while cursor < len(packed):
        tag = packed[cursor]; cursor += 1
        length = tag+1 if tag < 128 else (tag&127)+3
        if len(output)+length > expected_size:
            raise ValueError('decoded output exceeds expected length')
        if tag < 128:
            if cursor+length > len(packed):
                raise ValueError('truncated literal')
            output.extend(packed[cursor:cursor+length]); cursor += length
        else:
            if cursor+2 > len(packed):
                raise ValueError('truncated match distance')
            distance = int.from_bytes(packed[cursor:cursor+2],'little'); cursor += 2
            if not 1 <= distance <= len(output):
                raise ValueError('invalid backward distance')
            for _ in range(length):
                output.append(output[-distance])
    if len(output) != expected_size:
        raise ValueError('decoded output shorter than expected length')
    return bytes(output)
