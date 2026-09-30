#!/usr/bin/env python3
"""
Load test for config reload (SIGHUP): a real HBlink4 process, N simulated hotspots
logged in over HomeBrew with pings and a live voice stream, then the config file is
rewritten and HUP'd mid-stream.

Passes when:
  - no hotspot but the one whose passphrase changed is disconnected or logs in again;
  - the stream keeps reaching every listener across the reload (no gap);
  - a talkgroup added to one hotspot reaches that hotspot, and only that one;
  - the passphrase change disconnects exactly one hotspot (MSTCL).

    .venv/bin/python scripts/reload_load_test.py [--hotspots 25]
"""
import argparse
import asyncio
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from hashlib import sha256

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_ID = 302708301
TG_A, TG_NEW, TG_B = 3027, 3100, 3026


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def config(port, hotspots, changes=None):
    changes = changes or {}
    pats = []
    for i in range(hotspots):
        rid = BASE_ID + i
        pw, ts2 = changes.get(rid, (f'pw-{rid}', [TG_B]))
        pats.append({'name': f'hotspot-{rid}', 'description': '', 'match': {'ids': [rid]},
                     'config': {'passphrase': pw, 'trust': False,
                                'slot1_talkgroups': [TG_A], 'slot2_talkgroups': ts2}})
    return {'global': {'bind_ipv4': '127.0.0.1', 'port_ipv4': port, 'disable_ipv6': True,
                       'max_missed': 3, 'timeout_duration': 30, 'stream_timeout': 2.0,
                       'stream_hang_time': 3.0, 'user_cache': {'timeout': 600},
                       'logging': {'file': os.path.join(tempfile.gettempdir(), 'hb4-reload-test.log'),
                                   'console_level': 'INFO', 'file_level': 'INFO', 'retention_days': 1}},
            'dashboard': {'enabled': False},
            'repeater_configurations': {'patterns': pats}}


def dmrd(seq, src, dst, rid, slot, stream_id, frame_type, dtype):
    """src: the operator's 7-digit radio ID (3 bytes); rid: the hotspot's ID, which
    may carry a 2-digit suffix (4 bytes)."""
    bits = (0x80 if slot == 2 else 0) | (frame_type << 4) | dtype
    return (b'DMRD' + bytes([seq & 0xFF]) + src.to_bytes(3, 'big') + dst.to_bytes(3, 'big')
            + rid.to_bytes(4, 'big') + bytes([bits]) + stream_id.to_bytes(4, 'big') + bytes(33)
            + bytes(2))                                        # BER, RSSI: HBP frames are 55 bytes


class Hotspot(asyncio.DatagramProtocol):
    def __init__(self, rid, passphrase, rpto):
        self.rid, self.pw, self.rpto = rid, passphrase, rpto
        self.key = rid.to_bytes(4, 'big')
        self.state = 'new'
        self.challenges = 0            # RPTACK+salt: 1 per login
        self.mstcl = 0
        self.pongs = 0
        self.rx: dict = {}             # tgid -> [times]
        self.connected = asyncio.Event()

    def connection_made(self, transport):
        self.t = transport
        self.state = 'login'
        self.send(b'RPTL' + self.key)

    def send(self, pkt):
        """A login step, remembered so it can be sent again if the answer is lost (UDP),
        as MMDVMHost does."""
        self.last, self.sent_at = pkt, time.monotonic()
        self.t.sendto(pkt)

    def retry(self):
        if self.state not in ('connected', 'closed') and time.monotonic() - self.sent_at > 2.0:
            if self.state == 'login':
                self.last = b'RPTL' + self.key
            self.send(self.last)

    def datagram_received(self, data, addr):
        if data[:6] == b'RPTACK' and len(data) == 10 and self.state == 'login':
            self.challenges += 1
            self.send(b'RPTK' + self.key + bytes.fromhex(sha256(data[6:10] + self.pw.encode()).hexdigest()))
            self.state = 'auth'
        elif data[:6] == b'RPTACK' and self.state == 'auth':
            cfg = (b'RPTC' + self.key + b'VE7TEST '.ljust(8) + b'442175000447175000' + b'25'
                   + b'01' + b'49.2600' + b'-123.2400' + b'010' + b'Vancouver'.ljust(20)
                   + b'test'.ljust(19) + b'2' + b''.ljust(124) + b'loadtest'.ljust(40) + b'test'.ljust(40))
            self.send(cfg.ljust(302, b' ')[:302])
            self.state = 'config'
        elif data[:6] == b'RPTACK' and self.state == 'config':
            self.send(b'RPTO' + self.key + self.rpto.encode())
            self.state = 'options'
        elif data[:6] == b'MSTNAK' and self.state in ('auth', 'config', 'options'):
            self.state = 'login'                     # start over, as a real client does
            self.send(b'RPTL' + self.key)
        elif data[:6] == b'RPTACK' and self.state == 'options':
            self.state = 'connected'
            self.connected.set()
        elif data[:7] == b'MSTPONG':
            self.pongs += 1
        elif data[:5] == b'MSTCL':
            self.mstcl += 1
            self.state = 'closed'
        elif data[:4] == b'DMRD':
            tg = int.from_bytes(data[8:11], 'big')
            self.rx.setdefault(tg, []).append(time.monotonic())


async def main(n):
    port = free_port()
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, 'config.json')
    json.dump(config(port, n), open(path, 'w'))
    # Console output to a file: a pipe nobody reads fills at 64 KB and blocks the server.
    console = open(os.path.join(tmp, 'console.log'), 'w')
    proc = subprocess.Popen([sys.executable, 'run_hblink.py', path], cwd=HERE,
                            stdout=console, stderr=subprocess.STDOUT, text=True)
    try:
        await asyncio.sleep(2.0)
        loop = asyncio.get_running_loop()
        hs = []
        for i in range(n):
            rid = BASE_ID + i
            proto = Hotspot(rid, f'pw-{rid}', f'TS1={TG_A};TS2={TG_B},{TG_NEW}')
            await loop.create_datagram_endpoint(lambda p=proto: p, remote_addr=('127.0.0.1', port))
            hs.append(proto)
            await asyncio.sleep(0.02)                  # logins arrive spread out, as in life
        async def pinger():
            while True:
                for h in hs:
                    if h.state == 'connected':
                        h.t.sendto(b'RPTPING' + h.key)
                    else:
                        h.retry()
                await asyncio.sleep(1.0)

        ping = asyncio.create_task(pinger())
        try:
            await asyncio.wait_for(asyncio.gather(*(h.connected.wait() for h in hs)), 60)
        except asyncio.TimeoutError:
            print(f'only {sum(h.state == "connected" for h in hs)} of {n} logged in; states:',
                  sorted({h.state for h in hs}))
            for h in [h for h in hs if h.state != 'connected'][:4]:
                print(f'  {h.rid}: state {h.state}, challenges {h.challenges}, '
                      f'last sent {h.last[:4]!r} {time.monotonic() - h.sent_at:.1f}s ago')
            raise
        print(f'{n} hotspots logged in')
        logins = {h.rid: h.challenges for h in hs}      # logins so far (retries included)

        async def talker(h, slot, tg, secs, stream_id):
            h.t.sendto(dmrd(0, h.rid // 100, tg, h.rid, slot, stream_id, 2, 1))       # voice LC header
            end, seq = time.monotonic() + secs, 1
            while time.monotonic() < end:
                vseq = (seq - 1) % 6
                h.t.sendto(dmrd(seq, h.rid // 100, tg, h.rid, slot, stream_id, 1 if vseq == 0 else 0, vseq))
                seq += 1
                await asyncio.sleep(0.06)
            h.t.sendto(dmrd(seq, h.rid // 100, tg, h.rid, slot, stream_id, 2, 2))     # terminator

        stream = asyncio.create_task(talker(hs[0], 1, TG_A, 8.0, 0x11111111))
        await asyncio.sleep(3.0)

        target_tg, target_pw = hs[5].rid, hs[9].rid
        # hotspot 6 gains TG 3100 (and so does hotspot 2, which will transmit on it:
        # HBlink4 also refuses a transmission on a talkgroup the sender may not use).
        json.dump(config(port, n, {target_tg: (f'pw-{target_tg}', [TG_B, TG_NEW]),
                                   hs[1].rid: (f'pw-{hs[1].rid}', [TG_B, TG_NEW]),
                                   target_pw: ('rotated-passphrase', [TG_B])}), open(path, 'w'))
        t_reload = time.monotonic()
        proc.send_signal(signal.SIGHUP)
        print('SIGHUP sent mid-stream')
        await stream
        await asyncio.sleep(3.0)                                 # past stream_hang_time
        await talker(hs[1], 2, TG_NEW, 1.5, 0x22222222)
        await asyncio.sleep(1.0)
        ping.cancel()

        fails = []
        for i, h in enumerate(hs):
            again = h.challenges - logins[h.rid]          # logins after the test began
            if i == 9:
                if h.mstcl != 1:
                    fails.append(f'{h.rid}: passphrase changed but MSTCL x{h.mstcl}')
                continue
            if h.mstcl or again:
                fails.append(f'{h.rid}: disconnected x{h.mstcl}, logged in again x{again}')
        listeners = [h for i, h in enumerate(hs) if i not in (0, 9)]
        for h in listeners:
            ts = h.rx.get(TG_A, [])
            near = [t for t in ts if t_reload - 1.0 <= t <= t_reload + 1.0]
            gaps = [b - a for a, b in zip(ts, ts[1:]) if a >= t_reload - 1.0 and b <= t_reload + 1.0]
            if len(near) < 20 or (gaps and max(gaps) > 0.3):
                fails.append(f'{h.rid}: stream interrupted around the reload '
                             f'({len(near)} frames in 2 s, largest gap {max(gaps or [0]):.2f}s)')
        got_new = [h.rid for h in hs if h.rx.get(TG_NEW)]
        if got_new != [hs[5].rid]:
            fails.append(f'TG {TG_NEW} reached {got_new}, expected only {hs[5].rid}')
        print(f'listeners: {len(listeners)}; frames per listener on TG {TG_A}: '
              f'{min(len(h.rx.get(TG_A, [])) for h in listeners)}-{max(len(h.rx.get(TG_A, [])) for h in listeners)}')
        print(f'TG {TG_NEW} reached: {got_new}; hotspot {hs[9].rid} MSTCL x{hs[9].mstcl}')
        print(f'pongs: {min(h.pongs for h in listeners)}-{max(h.pongs for h in listeners)} per listener')
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        console.close()
        out = open(console.name).read()
    reload_lines = [l for l in out.splitlines() if 'RELOAD' in l]
    print('\n'.join(reload_lines) or '(no RELOAD line in the log)')
    if fails:
        print('FAIL\n  ' + '\n  '.join(fails))
        return 1
    print(f'PASS: {n} hotspots, reload mid-stream, zero reconnects')
    return 0


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--hotspots', type=int, default=25)
    sys.exit(asyncio.run(main(ap.parse_args().hotspots)))
