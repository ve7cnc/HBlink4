"""
Pattern-level slot remaps (RepeaterConfig.translations).

On a hotspot server every talkgroup arriving over OpenBridge lands on the one slot its
`talkgroup_slots` names, server-wide. A duplex hotspot that wants some of them on TS1
needs a per-connection remap, and until now only a *trusted* repeater could declare
one (in RPTO). Hotspots are untrusted, so the remap now comes from the config, which
the operator controls:

    "translations": {"2": ["3027:1"]}   network TS2/3027 <-> the hotspot's TS1/3027

What must hold:
- the maps are in place from login, without any RPTO;
- traffic both ways: network TS2/3027 is delivered on the hotspot's TS1, and its
  TS1/3027 goes out as network TS2/3027;
- an untrusted repeater's RPTO keeps them (and may name a remapped talkgroup by the
  slot it hears it on); a trusted repeater's own RPTO translations replace them;
- a SIGHUP reload changes them in place, without disconnecting anyone;
- a bad entry fails the load (a reload keeps the running config);
- a pattern without `translations` behaves exactly as before.
"""

import copy
import json
import logging
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hblink4 import hblink as hblink_mod
from hblink4.access_control import RepeaterConfig
from hblink4.hblink import HBProtocol, reload_config
from hblink4.models import RepeaterState

DUPLEX, SIMPLEX = 302708301, 302708302


def tg(n):
    return n.to_bytes(3, 'big')


def tgs(values):
    return {tg(v) for v in values}


def pattern(rid, ts2, translations=None, trust=False):
    cfg = {'passphrase': f'pw-{rid}', 'trust': trust,
           'slot1_talkgroups': [], 'slot2_talkgroups': ts2}
    if translations is not None:
        cfg['translations'] = translations
    return {'name': f'hotspot-{rid}', 'description': '', 'match': {'ids': [rid]}, 'config': cfg}


BASE = {
    'global': {'user_cache': {'timeout': 600}, 'port_ipv4': 62031},
    'dashboard': {'enabled': False},
    'repeater_configurations': {'patterns': [
        pattern(DUPLEX, [3027, 3026, 91], {'2': ['3027:1', '3026:1']}),
        pattern(SIMPLEX, [3027, 3026, 91]),
    ]},
}


class FakeTransport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr=None):
        self.sent.append((data, addr))


class PatternTranslationTestCase(unittest.TestCase):
    def setUp(self):
        self._saved = hblink_mod.CONFIG
        hblink_mod.CONFIG = copy.deepcopy(BASE)
        hblink_mod.LOGGER = logging.getLogger('test-pattern-translations')
        self.hb = HBProtocol()
        self.hb.transport = self.hb._port = FakeTransport()
        self.addrs = {}
        for i, rid in enumerate((DUPLEX, SIMPLEX)):
            self.connect(rid, ('198.51.100.%d' % (10 + i), 62031))
        self.file = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
        self.file.close()

    def tearDown(self):
        hblink_mod.CONFIG = self._saved
        os.unlink(self.file.name)

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
        return self.hb._repeaters.get(rid.to_bytes(4, 'big'))

    def reload(self, cfg):
        with open(self.file.name, 'w') as f:
            json.dump(cfg, f)
        return reload_config(self.file.name, [self.hb])

    def with_duplex(self, translations, ts2=(3027, 3026, 91), trust=False):
        cfg = copy.deepcopy(BASE)
        cfg['repeater_configurations']['patterns'][0] = pattern(DUPLEX, list(ts2), translations, trust)
        return cfg

    # -- from login -----------------------------------------------------------

    def test_maps_are_in_place_from_login(self):
        d = self.rep(DUPLEX)
        self.assertEqual(d.outbound_map, {(2, tg(3027)): (1, tg(3027)), (2, tg(3026)): (1, tg(3026))})
        self.assertEqual(d.inbound_map, {(1, tg(3027)): (2, tg(3027)), (1, tg(3026)): (2, tg(3026))})
        # The subscription stays in network vocabulary.
        self.assertEqual(d.slot2_talkgroups, tgs([3027, 3026, 91]))

    def test_a_pattern_without_translations_is_unchanged(self):
        s = self.rep(SIMPLEX)
        self.assertEqual((s.inbound_map, s.outbound_map), ({}, {}))
        self.assertIsNone(RepeaterConfig(passphrase='x').translations)

    # -- traffic ----------------------------------------------------------------

    def test_network_ts2_is_delivered_on_the_duplex_hotspots_ts1(self):
        targets = self.hb._calculate_stream_targets(('openbridge', 'hs1-ng1'), 2, tg(3027),
                                                    b'\x00\x00\x00\x01', tg(3027083))
        self.assertIn(DUPLEX.to_bytes(4, 'big'), targets)
        self.assertIn(SIMPLEX.to_bytes(4, 'big'), targets)
        self.assertEqual(self.rep(DUPLEX).outbound_map[(2, tg(3027))], (1, tg(3027)))
        # An unmapped talkgroup stays on TS2 for both.
        self.assertNotIn((2, tg(91)), self.rep(DUPLEX).outbound_map)

    def test_the_duplex_hotspots_ts1_goes_out_as_network_ts2(self):
        key = DUPLEX.to_bytes(4, 'big')
        self.assertTrue(self.hb._check_inbound_routing(key, 1, tg(3027)))
        # Keying the network-side address of a remapped talkgroup is refused.
        self.assertFalse(self.hb._check_inbound_routing(key, 2, tg(3027)))
        self.assertTrue(self.hb._check_inbound_routing(key, 2, tg(91)))
        self.assertFalse(self.hb._check_inbound_routing(key, 1, tg(91)))

    # -- RPTO -------------------------------------------------------------------

    def test_an_untrusted_rpto_keeps_the_pattern_maps(self):
        d = self.rep(DUPLEX)
        self.hb._handle_options(d.repeater_id, b'TS1=3027;TS2=91', self.addrs[DUPLEX])
        self.assertEqual(d.outbound_map[(2, tg(3027))], (1, tg(3027)))
        # TS1=3027 is the hotspot naming 3027 by the slot it hears it on: network TS2.
        self.assertEqual(d.slot2_talkgroups, tgs([3027, 91]))

    def test_an_untrusted_rpto_cannot_add_its_own_translations(self):
        d = self.rep(DUPLEX)
        with self.assertLogs('test-pattern-translations', level='WARNING'):
            self.hb._handle_options(d.repeater_id, b'TS2=91:1', self.addrs[DUPLEX])
        self.assertNotIn((2, tg(91)), d.outbound_map)
        self.assertEqual(d.outbound_map[(2, tg(3027))], (1, tg(3027)))

    def test_a_trusted_rpto_with_translations_replaces_the_pattern_maps(self):
        self.reload(self.with_duplex({'2': ['3027:1']}, trust=True))
        d = self.rep(DUPLEX)
        self.hb._handle_options(d.repeater_id, b'TS2=91:1', self.addrs[DUPLEX])
        self.assertEqual(d.outbound_map, {(2, tg(91)): (1, tg(91))})
        self.hb._handle_options(d.repeater_id, b'TS2=91', self.addrs[DUPLEX])
        self.assertEqual(d.outbound_map, {(2, tg(3027)): (1, tg(3027))})   # back to the pattern's

    # -- reload -----------------------------------------------------------------

    def test_a_reload_changes_the_maps_in_place(self):
        d = self.rep(DUPLEX)
        self.assertTrue(self.reload(self.with_duplex({'2': ['91:1']})))
        self.assertIs(self.rep(DUPLEX), d)
        self.assertEqual(d.outbound_map, {(2, tg(91)): (1, tg(91))})
        self.assertTrue(self.reload(self.with_duplex(None)))
        self.assertEqual((d.inbound_map, d.outbound_map), ({}, {}))
        self.assertEqual(self.hb.transport.sent, [], 'a reload sent something to a repeater')

    def test_a_reload_reapplies_a_standing_rpto_against_new_maps(self):
        d = self.rep(DUPLEX)
        self.hb._handle_options(d.repeater_id, b'TS2=91,3027', self.addrs[DUPLEX])
        self.reload(self.with_duplex({'2': ['91:1']}))
        self.assertEqual(d.outbound_map, {(2, tg(91)): (1, tg(91))})
        self.assertEqual(d.slot2_talkgroups, tgs([91, 3027]))

    def test_a_bad_entry_fails_the_load_and_changes_nothing(self):
        matcher = self.hb._matcher
        for bad in ({'3': ['3027:1']}, {'2': ['3027']}, {'2': ['*:1']}, {'2': '3027:1'},
                    {'2': ['3027:3']}):
            with self.assertLogs('test-pattern-translations', level='ERROR'):
                self.assertFalse(self.reload(self.with_duplex(bad)), bad)
            self.assertIs(self.hb._matcher, matcher)
        self.assertEqual(self.rep(DUPLEX).outbound_map[(2, tg(3027))], (1, tg(3027)))


if __name__ == '__main__':
    unittest.main()
