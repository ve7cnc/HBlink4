#!/usr/bin/env python3
"""
Live test for PTT activation: a real HBlink4 process and simulated hotspots logged in
over HomeBrew, all on TS2, with a short `ptt_timeout`.

Passes when:
  - a talkgroup in the envelope is not delivered until the hotspot keys it;
  - once keyed, it is delivered, and only to the hotspot that keyed it;
  - other hotspots' traffic on it (network traffic, to the keyer) does not renew it:
    it drops `ptt_timeout` after the keyer's own last transmission;
  - keying it again brings it back;
  - a SIGHUP reload of another hotspot's full time list, mid-activation, neither
    disconnects anyone nor drops the activation.

    .venv/bin/python scripts/ptt_live_test.py
"""
import asyncio
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, 'scripts'))
from reload_load_test import Hotspot, dmrd, free_port   # noqa: E402

A, B, C = 302708301, 302708302, 302708303
FULL, TG_P, TG_Q = 3027, 3026, 3100
TIMEOUT = 8
HANG = 2.0


def config(port, c_full=(FULL,)):
    def pat(rid, full):
        return {'name': f'hotspot-{rid}', 'description': '', 'match': {'ids': [rid]},
                'config': {'passphrase': f'pw-{rid}', 'trust': False,
                           'slot1_talkgroups': [], 'slot2_talkgroups': list(full),
                           'ptt_talkgroups': [TG_P, TG_Q], 'ptt_timeout': TIMEOUT,
                           'ptt_slot': 2}}
    return {'global': {'bind_ipv4': '127.0.0.1', 'port_ipv4': port, 'disable_ipv6': True,
                       'max_missed': 3, 'timeout_duration': 30, 'stream_timeout': 2.0,
                       'stream_hang_time': HANG, 'user_cache': {'timeout': 600},
                       'logging': {'file': os.path.join(tempfile.gettempdir(), 'hb4-ptt-test.log'),
                                   'console_level': 'INFO', 'file_level': 'INFO', 'retention_days': 1}},
            'dashboard': {'enabled': False},
            'repeater_configurations': {'patterns': [pat(A, [FULL]), pat(B, [FULL]), pat(C, c_full)]}}


async def main():
    port = free_port()
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, 'config.json')
    json.dump(config(port), open(path, 'w'))
    console = open(os.path.join(tmp, 'console.log'), 'w')
    proc = subprocess.Popen([sys.executable, 'run_hblink.py', path], cwd=HERE,
                            stdout=console, stderr=subprocess.STDOUT, text=True)
    fails = []
    try:
        await asyncio.sleep(2.0)
        loop = asyncio.get_running_loop()
        hs = {}
        for rid in (A, B, C):
            h = Hotspot(rid, f'pw-{rid}', '')
            await loop.create_datagram_endpoint(lambda p=h: p, remote_addr=('127.0.0.1', port))
            hs[rid] = h

        # These hotspots send no RPTO: answer the config ACK as connected.
        def connected_on_config(h):
            orig = h.datagram_received

            def recv(data, addr):
                if data[:6] == b'RPTACK' and h.state == 'config':
                    h.state = 'connected'
                    h.connected.set()
                    return
                orig(data, addr)
            h.datagram_received = recv
        for h in hs.values():
            connected_on_config(h)

        async def pinger():
            while True:
                for h in hs.values():
                    if h.state == 'connected':
                        h.t.sendto(b'RPTPING' + h.key)
                    else:
                        h.retry()
                await asyncio.sleep(1.0)
        ping = asyncio.create_task(pinger())
        await asyncio.wait_for(asyncio.gather(*(h.connected.wait() for h in hs.values())), 30)
        logins = {rid: h.challenges for rid, h in hs.items()}
        print('3 hotspots logged in')

        sid = [0x30000000]

        async def talk(rid, tg, secs=1.0):
            h = hs[rid]
            sid[0] += 1
            h.t.sendto(dmrd(0, rid // 100, tg, rid, 2, sid[0], 2, 1))
            end, seq = time.monotonic() + secs, 1
            while time.monotonic() < end:
                vseq = (seq - 1) % 6
                h.t.sendto(dmrd(seq, rid // 100, tg, rid, 2, sid[0], 1 if vseq == 0 else 0, vseq))
                seq += 1
                await asyncio.sleep(0.06)
            h.t.sendto(dmrd(seq, rid // 100, tg, rid, 2, sid[0], 2, 2))
            await asyncio.sleep(HANG + 0.5)          # past hang time, so the next call is free

        def got(rid, tg, since):
            return len([t for t in hs[rid].rx.get(tg, []) if t >= since])

        def check(ok, what):
            print(('  ok   ' if ok else '  FAIL ') + what)
            if not ok:
                fails.append(what)

        # 1. In the envelope, not keyed: not delivered.
        t = time.monotonic()
        await talk(B, TG_P)
        check(got(A, TG_P, t) == 0, f'A does not hear {TG_P} before keying it')

        # 2. A keys it: delivered to A, and only A.
        await talk(A, TG_P, 0.5)
        t = time.monotonic()
        await talk(B, TG_P)
        check(got(A, TG_P, t) > 5, f'A hears {TG_P} after keying it ({got(A, TG_P, t)} frames)')
        check(got(C, TG_P, t) == 0, f'C (never keyed it) does not')

        # 3. B keeps talking on it; A stays quiet. Network traffic must not renew A.
        t_a_last = time.monotonic()                   # A's last transmission ended ~3 s ago
        while time.monotonic() - t_a_last < TIMEOUT + 2:
            await talk(B, TG_P, 0.5)
        t = time.monotonic()
        await talk(B, TG_P)
        check(got(A, TG_P, t) == 0,
              f'A stops hearing {TG_P} {TIMEOUT}s after its own last over, despite B talking')

        # 4. Keying it again brings it back.
        await talk(A, TG_P, 0.5)
        t = time.monotonic()
        await talk(B, TG_P)
        check(got(A, TG_P, t) > 5, 'keying it again brings it back')

        # 5. A activates TG_Q; C's full time list changes by SIGHUP; A keeps TG_Q.
        await talk(A, TG_Q, 0.5)
        json.dump(config(port, c_full=(FULL, 91)), open(path, 'w'))
        proc.send_signal(signal.SIGHUP)
        await asyncio.sleep(1.0)
        t = time.monotonic()
        await talk(B, TG_Q)
        check(got(A, TG_Q, t) > 5, f'A still hears {TG_Q} after a reload of C\'s list')
        again = {rid: h.challenges - logins[rid] for rid, h in hs.items()}
        check(not any(again.values()) and not any(h.mstcl for h in hs.values()),
              f'nobody disconnected or logged in again ({again})')
        ping.cancel()
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        console.close()
        out = open(console.name).read()
    print('\n'.join(l for l in out.splitlines() if 'PTT' in l or 'RELOAD' in l))
    if fails:
        print('FAIL\n  ' + '\n  '.join(fails))
        return 1
    print('PASS: PTT activation, renewal from local traffic only, expiry, reload-safe')
    return 0


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
