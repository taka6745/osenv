"""Host-clock timing from QMP CPU release to a verified client completion.

QMP timestamps are host epoch microseconds. QEMU network capture timestamps
use the guest virtual clock and cannot be mixed with these measurements.
"""
import time


def sample_clock():
    """Bracket the epoch sample with monotonic readings to bound sample skew."""
    before = time.monotonic_ns()
    wall = time.time_ns()
    after = time.monotonic_ns()
    return {'wall_ns':wall, 'monotonic_before_ns':before, 'monotonic_after_ns':after}


def _integer(value, name):
    if type(value) is not int:
        raise ValueError(name+' must be an integer')
    return value


def event_wall_ns(event):
    timestamp = event['timestamp']
    seconds = _integer(timestamp['seconds'], 'QMP seconds')
    micros = _integer(timestamp['microseconds'], 'QMP microseconds')
    if seconds < 0 or not 0 <= micros < 1_000_000:
        raise ValueError('invalid QMP timestamp')
    return seconds*1_000_000_000+micros*1000


def _sample(sample):
    wall = _integer(sample['wall_ns'], 'wall_ns')
    before = _integer(sample['monotonic_before_ns'], 'monotonic_before_ns')
    after = _integer(sample['monotonic_after_ns'], 'monotonic_after_ns')
    if wall < 0 or before < 0 or after < before:
        raise ValueError('invalid clock sample ordering')
    return wall, before, after


def returned_request_timing(events, before_sample, completion_sample,
                            max_clock_shift_ns=1_000_000):
    """Measure first RESUME to completion; fail closed on ambiguous execution.

    before_sample must precede issuing cont, completion_sample must immediately
    follow independently verified receipt of the complete response. Endpoint
    samples detect net wall-clock drift; they do not prove absence of an offset
    that changed and then reversed between samples. A shared QEMU/client host
    clock is required. Completion includes host socket/client processing costs.
    """
    tolerance = _integer(max_clock_shift_ns, 'max_clock_shift_ns')
    if tolerance < 0:
        raise ValueError('negative clock shift tolerance')
    start_wall, start_before, start_after = _sample(before_sample)
    done_wall, done_before, done_after = _sample(completion_sample)
    if done_before < start_after or done_wall < start_wall:
        raise ValueError('completion precedes before sample')
    wall_elapsed = done_wall-start_wall
    mono_min = done_before-start_after
    mono_max = done_after-start_before
    shift_min = wall_elapsed-mono_max
    shift_max = wall_elapsed-mono_min
    # Entire uncertainty interval must remain within tolerance: a wide sample
    # must not conceal a potentially unacceptable shift.
    if shift_min < -tolerance or shift_max > tolerance:
        raise ValueError('wall/monotonic drift or sample uncertainty exceeds bound')
    indexed = [(index, event, event_wall_ns(event)) for index,event in enumerate(events)
               if event.get('event') in ('RESUME','RESET','STOP')]
    resumes = [(index,stamp) for index,event,stamp in indexed if event['event']=='RESUME']
    if not resumes:
        raise ValueError('missing QMP RESUME')
    index, resume_wall = resumes[0]
    if not start_wall <= resume_wall <= done_wall:
        raise ValueError('QMP RESUME outside measured interval')
    last_stamp = resume_wall
    for event_index,event,stamp in indexed:
        if event_index <= index:
            continue
        if stamp < last_stamp:
            raise ValueError('QMP execution event timestamps moved backward')
        last_stamp = stamp
        if stamp <= done_wall:
            raise ValueError('unexpected '+event['event']+' during measured boot')
    elapsed = done_wall-resume_wall
    return {'qmp_resume_wall_ns':resume_wall,
            'client_complete_wall_ns':done_wall,
            'cpu_release_to_returned_request_ns':elapsed,
            'cpu_release_to_returned_request_seconds':elapsed/1_000_000_000,
            'qmp_timestamp_resolution_ns':1000,
            'clock_shift_interval_ns':[shift_min,shift_max],
            'max_clock_shift_ns':tolerance,
            'elapsed_error_bound_ns':tolerance+1000,
            'before_sample':before_sample, 'completion_sample':completion_sample,
            'scope':'QEMU first CPU RESUME to externally verified complete client response; includes firmware, disk boot, DHCP, network and host client processing after release; excludes controller preparation. Not physical power-on. QMP and client share host wall clock; PCAP virtual timestamps are excluded. Clock samples bound net drift only.'}
