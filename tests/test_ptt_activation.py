"""
PTT activation (RepeaterConfig.ptt_talkgroups / ptt_timeout / ptt_slot).

A pattern's slot lists are its full time talkgroups. `ptt_talkgroups` is the envelope:
talkgroups the repeater may bring up by keying them. Each local slot carries at most one
activation, renewed only by the repeater's own traffic, dropped `ptt_timeout` seconds
after the last of it. Activations are runtime state on the connection.

What must hold:
- keying a talkgroup in the envelope brings it up on that slot; outside it, refused;
- a full time talkgroup makes no activation; a second activation replaces the first;
- TS1 and TS2 are independent; delivery is full time or the activation, nothing else;
- local traffic renews the timer, network traffic never does; expiry by one sweep;
- a SIGHUP reload replaces the full time lists and the envelope and keeps activations;
  a talkgroup leaving the envelope runs out its timer, never cut, never renewed;
- RPTO statics are full time, intersected against the whole envelope;
- `ptt_slot`: an activation keyed on the other slot is carried on that network slot and
  heard back on the slot it was keyed on (a duplex hotspot on a TS2-only server);
- a pattern without `ptt_talkgroups` behaves exactly as before.
"""

import copy
import json
import logging
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hblink4 import hblink as hblink_mod
from hblink4.access_control import RepeaterConfig
from hblink4.hblink import HBProtocol, reload_config
from hblink4.models import RepeaterState

A, B, PLAIN = 302708301, 302708302, 302708303
OBP = ('openbridge', 'hs1-ng1')


def tg(n):
    return n.to_bytes(3, 'big')


def tgs(values):
    return {tg(v) for v in values}


def pattern(rid, ts2, ptt=None, timeout=900, ptt_slot=None, ts1=()):
    cfg = {'passphrase': f'pw-{rid}', 'trust': False,
           'slot1_talkgroups': list(ts1), 'slot2_talkgroups': list(ts2)}
    if ptt is not None:
        cfg['ptt_talkgroups'] = list(ptt)
        cfg['ptt_timeout'] = timeout
    if ptt_slot is not None:
        cfg['ptt_slot'] = ptt_slot
    return {'name': f'hotspot-{rid}', 'description': '', 'match': {'ids': [rid]}, 'config': cfg}


ENVELOPE = [3027, 302, 3026, 3100, 31771]


def base(a=None, b=None):
    return {
        'global': {'user_cache': {'timeout': 600}, 'port_ipv4': 62031},
        'dashboard': {'enabled': False},
        'repeater_configurations': {'patterns': [
            a or pattern(A, [3027, 302], ENVELOPE),
            b or pattern(B, [3027], ENVELOPE),
            pattern(PLAIN, [3027, 302]),
        ]},
    }


class FakeTransport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr=None):
        self.sent.append((data, addr))


class PttTestCase(unittest.TestCase):
    def setUp(self):
        self._saved = hblink_mod.CONFIG
        hblink_mod.CONFIG = copy.deepcopy(base())
        hblink_mod.LOGGER = logging.getLogger('test-ptt')
        self.hb = HBProtocol()
        self.hb.transport = self.hb._port = FakeTransport()
        self.events = []
        self.hb._events = mock.Mock()
        self.hb._events.emit.side_effect = lambda t, d: self.events.append((t, d))
        self.addrs = {}
        for i, rid in enumerate((A, B, PLAIN)):
            self.connect(rid, ('198.51.100.%d' % (10 + i), 62031))
        self.file = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
        self.file.close()
        self.stream = 0
        self.now = 1_000_000.0
        self.clock = mock.patch.object(hblink_mod, 'time', side_effect=lambda: self.now)
        self.clock.start()

    def tearDown(self):
        self.clock.stop()
        hblink_mod.CONFIG = self._saved
        os.unlink(self.file.name)

    # -- helpers ----------------------------------------------------------------

    def connect(self, rid, addr):
        key = rid.to_bytes(4, 'big')
        st = RepeaterState(repeater_id=key, ip=addr[0], port=addr[1])
        st.connection_state, st.connected, st.authenticated = 'connected', True, True
        st.callsign = b'VE7KA   '
        self.hb._repeaters[key] = st
        self.hb._load_repeater_tg_config(key, st)
        self.addrs[rid] = addr
        return st

    def rep(self, rid):
        return self.hb._repeaters[rid.to_bytes(4, 'big')]

    def key(self, rid, slot, talkgroup):
        """The hotspot keys `talkgroup` on local `slot`; returns whether it was let in.
        The stream is ended at once (a short over)."""
        r = self.rep(rid)
        self.stream += 1
        sid = self.stream.to_bytes(4, 'big')
        ok = self.hb._handle_stream_start(r, tg(3027083), tg(talkgroup), slot, sid, call_type_bit=0)
        st = r.get_slot_stream(slot)
        if ok and st is not None and st.stream_id == sid:
            self.hb._end_stream(st, r.repeater_id, slot, self.now, 'terminator')
            r.set_slot_stream(slot, None)
        return ok

    def heard(self, rid, slot, talkgroup):
        """Would network traffic on (slot, talkgroup) reach this hotspot?"""
        self.stream += 1
        targets = self.hb._calculate_stream_targets(OBP, slot, tg(talkgroup),
                                                    self.stream.to_bytes(4, 'big'), tg(3020001))
        return rid.to_bytes(4, 'big') in targets

    def active(self, rid):
        return {s: int.from_bytes(a.tgid, 'big') for s, a in self.rep(rid).ptt_active.items()}

    def reload(self, cfg):
        with open(self.file.name, 'w') as f:
            json.dump(cfg, f)
        return reload_config(self.file.name, [self.hb])

    def later(self, seconds):
        self.now += seconds
        self.hb._ptt_sweep()


class Activation(PttTestCase):
    def test_ptt_activates_tg_in_envelope(self):
        self.assertFalse(self.heard(A, 2, 3026))
        self.assertTrue(self.key(A, 2, 3026))
        self.assertEqual(self.active(A), {2: 3026})
        self.assertTrue(self.heard(A, 2, 3026))
        self.assertFalse(self.heard(B, 2, 3026), 'one hotspot keyed it, not the other')

    def test_ptt_refused_outside_envelope(self):
        with self.assertLogs('test-ptt', level='WARNING') as logs:
            self.assertFalse(self.key(A, 2, 9999))
        self.assertIn('Inbound routing denied', '\n'.join(logs.output))
        self.assertEqual(self.active(A), {})
        self.assertFalse(self.heard(A, 2, 9999))

    def test_ptt_on_full_time_tg_creates_no_activation(self):
        self.assertTrue(self.key(A, 2, 3027))
        self.assertEqual(self.active(A), {})

    def test_second_activation_replaces_first(self):
        self.key(A, 2, 3026)
        self.key(A, 2, 3100)
        self.assertEqual(self.active(A), {2: 3100})
        self.assertFalse(self.heard(A, 2, 3026))
        self.assertTrue(self.heard(A, 2, 3100))

    def test_activation_is_per_slot(self):
        self.key(A, 1, 3026)
        self.key(A, 2, 3100)
        self.assertEqual(self.active(A), {1: 3026, 2: 3100})
        self.assertTrue(self.heard(A, 1, 3026))
        self.assertTrue(self.heard(A, 2, 3100))
        self.assertFalse(self.heard(A, 2, 3026))

    def test_downlink_delivers_full_time_or_active(self):
        self.key(A, 2, 3026)
        self.assertTrue(self.heard(A, 2, 3027))          # full time
        self.assertTrue(self.heard(A, 2, 3026))          # active
        self.assertFalse(self.heard(A, 2, 3100))         # in the envelope, not active
        self.assertFalse(self.heard(A, 1, 3027))         # full time on TS2 only

    def test_activation_is_reported(self):
        self.key(A, 2, 3026)
        kind, data = [e for e in self.events if e[0] == 'repeater_ptt'][-1]
        self.assertEqual(data['repeater_id'], A)
        self.assertEqual(data['ptt_active'], [{'slot': 2, 'talkgroup': 3026, 'net_slot': 2,
                                               'last_heard': self.now,
                                               'expires': self.now + 900}])
        snapshot = self.hb._prepare_repeater_event_data(self.rep(A).repeater_id, self.rep(A))
        self.assertEqual(snapshot['ptt_active'][0]['talkgroup'], 3026)
        self.assertEqual(snapshot['ptt_timeout'], 900)

    def test_a_pattern_without_ptt_is_unchanged(self):
        self.assertIsNone(self.rep(PLAIN).ptt_talkgroups)
        with self.assertLogs('test-ptt', level='WARNING'):
            self.assertFalse(self.key(PLAIN, 2, 3026))
        self.assertEqual(self.active(PLAIN), {})
        self.assertIsNone(self.hb._prepare_repeater_event_data(
            self.rep(PLAIN).repeater_id, self.rep(PLAIN))['ptt_timeout'])

    def test_bad_ptt_config_is_refused(self):
        for bad in ({'ptt_talkgroups': '3026'}, {'ptt_talkgroups': [0]},
                    {'ptt_timeout': 0}, {'ptt_timeout': True}, {'ptt_slot': 3}):
            with self.assertRaises(ValueError, msg=bad):
                RepeaterConfig(passphrase='x', **bad)


class RenewalAndExpiry(PttTestCase):
    def test_local_traffic_renews_timer(self):
        self.key(A, 2, 3026)
        self.later(800)
        self.key(A, 2, 3026)
        self.later(800)
        self.assertEqual(self.active(A), {2: 3026})
        self.assertTrue(self.heard(A, 2, 3026))

    def test_network_traffic_does_not_renew_timer(self):
        self.key(A, 2, 3026)
        started = self.rep(A).ptt_active[2].last_heard
        for _ in range(8):
            self.later(100)
            r = self.rep(A)
            # Network traffic delivered to the hotspot: an assumed (TX) stream on it.
            sid = os.urandom(4)
            self.hb._update_assumed_stream(r, 2, tg(3020001), tg(3026), sid, False, 3020001)
            self.hb._update_assumed_stream(r, 2, tg(3020001), tg(3026), sid, True, 3020001)
            self.assertTrue(r.get_slot_stream(2).is_assumed)
        self.assertEqual(self.rep(A).ptt_active[2].last_heard, started)
        self.later(101)
        self.assertEqual(self.active(A), {})
        self.assertFalse(self.heard(A, 2, 3026))

    def test_activation_expires_after_ptt_timeout(self):
        self.key(A, 2, 3026)
        self.later(899)
        self.assertEqual(self.active(A), {2: 3026})
        self.now += 1
        self.assertFalse(self.heard(A, 2, 3026), 'delivery checks expiry itself')
        self.hb._ptt_sweep()
        self.assertEqual(self.active(A), {})
        self.assertEqual([e for e in self.events if e[0] == 'repeater_ptt'][-1][1]['ptt_active'], [])

    def test_expiry_sweep_handles_many_connections(self):
        for i in range(50):
            key = (A + 100 + i).to_bytes(4, 'big')
            r = RepeaterState(repeater_id=key, ip='198.51.100.99', port=40000 + i)
            r.connection_state = 'connected'
            r.slot1_talkgroups, r.slot2_talkgroups = set(), tgs([3027])
            r.ptt_talkgroups, r.ptt_timeout = tgs(ENVELOPE), 900.0
            self.hb._repeaters[key] = r
            self.hb._ptt_uplink(r, 2, tg(3026 if i % 2 else 3100))
        self.key(A, 1, 3026)
        self.assertEqual(sum(len(r.ptt_active) for r in self.hb._repeaters.values()), 51)
        self.later(899)
        self.assertEqual(sum(len(r.ptt_active) for r in self.hb._repeaters.values()), 51)
        self.later(1)                            # one sweep takes them all
        self.assertFalse(any(r.ptt_active for r in self.hb._repeaters.values()))


class ReloadSafety(PttTestCase):
    def test_reload_preserves_ptt_active(self):
        self.key(A, 2, 3026)
        r = self.rep(A)
        self.assertTrue(self.reload(base(a=pattern(A, [3027, 302, 91], ENVELOPE))))
        self.assertIs(self.rep(A), r)
        self.assertEqual(self.active(A), {2: 3026})
        self.assertTrue(self.heard(A, 2, 3026))
        self.assertEqual(self.hb.transport.sent, [], 'a reload sent something to a hotspot')

    def test_reload_replaces_full_time_lists(self):
        self.reload(base(a=pattern(A, [91], ENVELOPE)))
        self.assertEqual(self.rep(A).slot2_talkgroups, tgs([91]))
        self.assertFalse(self.heard(A, 2, 3027))

    def test_reload_replaces_envelope(self):
        self.reload(base(a=pattern(A, [3027], [3026, 9999], timeout=600)))
        self.assertEqual(self.rep(A).ptt_talkgroups, tgs([3026, 9999]))
        self.assertEqual(self.rep(A).ptt_timeout, 600)
        self.assertTrue(self.key(A, 2, 9999))
        with self.assertLogs('test-ptt', level='WARNING'):
            self.assertFalse(self.key(A, 1, 3100))

    def test_envelope_removal_lets_existing_activation_expire(self):
        self.key(A, 2, 3026)
        self.later(300)
        self.reload(base(a=pattern(A, [3027], [3100])))
        self.assertEqual(self.active(A), {2: 3026}, 'not cut mid-QSO')
        self.assertTrue(self.key(A, 2, 3026), 'the QSO carries on until it runs out')
        self.later(600)
        self.assertEqual(self.active(A), {}, 'and is not renewed by it')
        with self.assertLogs('test-ptt', level='WARNING'):
            self.assertFalse(self.key(A, 2, 3026), 'nor activated again')

    def test_other_hotspots_undisturbed_by_one_users_edit(self):
        self.key(B, 2, 3100)                    # B mid-QSO on an activated talkgroup
        self.key(A, 2, 3026)
        # A's owner edits their full time list; Trestle renders and reloads.
        self.assertTrue(self.reload(base(a=pattern(A, [3027, 31771], ENVELOPE))))
        self.assertEqual(self.active(B), {2: 3100})
        self.assertTrue(self.heard(B, 2, 3100))
        self.assertTrue(self.key(B, 2, 3100))
        self.assertTrue(self.heard(A, 2, 31771))
        self.assertEqual(self.active(A), {2: 3026})

    def test_reload_reapplies_rpto_and_keeps_activation(self):
        r = self.rep(A)
        self.hb._handle_options(r.repeater_id, b'TS2=3027,3100', self.addrs[A])
        self.key(A, 2, 3026)
        self.reload(base(a=pattern(A, [3027, 302], ENVELOPE)))
        self.assertEqual(r.slot2_talkgroups, tgs([3027, 3100]))
        self.assertEqual(self.active(A), {2: 3026})


class Rpto(PttTestCase):
    def test_rpto_declared_tgs_are_full_time(self):
        r = self.rep(A)
        self.hb._handle_options(r.repeater_id, b'TS2=3027,302', self.addrs[A])
        self.assertTrue(self.key(A, 2, 302))
        self.assertEqual(self.active(A), {})

    def test_rpto_intersected_against_full_envelope(self):
        r = self.rep(A)
        with self.assertLogs('test-ptt', level='WARNING') as logs:
            self.hb._handle_options(r.repeater_id, b'TS2=3027,3100,9999', self.addrs[A])
        self.assertEqual(r.slot2_talkgroups, tgs([3027, 3100]), 'NOT just the full time list')
        self.assertIn('[9999]', '\n'.join(logs.output))
        self.assertTrue(self.heard(A, 2, 3100))

    def test_rpto_without_ptt_is_unchanged(self):
        r = self.rep(PLAIN)
        with self.assertLogs('test-ptt', level='WARNING'):
            self.hb._handle_options(r.repeater_id, b'TS2=3027,3100', self.addrs[PLAIN])
        self.assertEqual(r.slot2_talkgroups, tgs([3027]))


class NetworkSlot(PttTestCase):
    """A hotspot server with every talkgroup on network TS2 (ptt_slot 2)."""

    def setUp(self):
        super().setUp()
        self.reload(base(a=pattern(A, [3027], ENVELOPE, ptt_slot=2)))

    def test_keyed_on_ts1_is_carried_on_network_ts2_and_heard_on_ts1(self):
        self.assertTrue(self.key(A, 1, 3026))
        r = self.rep(A)
        self.assertEqual(r.ptt_active[1].net_slot, 2)
        self.assertEqual(r.inbound_map, {(1, tg(3026)): (2, tg(3026))})
        self.assertEqual(r.outbound_map, {(2, tg(3026)): (1, tg(3026))})
        self.assertTrue(self.heard(A, 2, 3026))

    def test_moving_it_to_the_other_slot_moves_it(self):
        self.key(A, 1, 3026)
        self.assertTrue(self.key(A, 2, 3026))
        r = self.rep(A)
        self.assertEqual(self.active(A), {2: 3026})
        self.assertEqual((r.inbound_map, r.outbound_map), ({}, {}))

    def test_expiry_removes_the_remap(self):
        self.key(A, 1, 3026)
        self.later(900)
        r = self.rep(A)
        self.assertEqual((r.inbound_map, r.outbound_map), ({}, {}))

    def test_a_full_time_tg_keyed_on_ts1_makes_no_activation(self):
        with self.assertLogs('test-ptt', level='WARNING'):
            self.assertFalse(self.key(A, 1, 3027))
        self.assertEqual(self.active(A), {})

    def test_reload_keeps_the_remap(self):
        self.key(A, 1, 3026)
        self.reload(base(a=pattern(A, [3027, 302], ENVELOPE, ptt_slot=2)))
        self.assertEqual(self.rep(A).outbound_map, {(2, tg(3026)): (1, tg(3026))})

    def test_beside_pattern_translations(self):
        cfg = base(a=pattern(A, [3027], ENVELOPE, ptt_slot=2))
        cfg['repeater_configurations']['patterns'][0]['config']['translations'] = {'2': ['3027:1']}
        self.reload(cfg)
        self.key(A, 1, 3026)
        r = self.rep(A)
        self.assertEqual(r.outbound_map, {(2, tg(3027)): (1, tg(3027)),
                                          (2, tg(3026)): (1, tg(3026))})
        self.later(900)
        self.assertEqual(r.outbound_map, {(2, tg(3027)): (1, tg(3027))})


if __name__ == '__main__':
    unittest.main()
