"""
Config reload on SIGHUP (reload_config / HBProtocol.reload_repeaters).

A hotspot server serves hundreds of logins on one port; every talkgroup edit must
reach the connection it concerns and no other. What must hold:

- a connected repeater's cached talkgroups follow its new pattern at once (the
  cache is what routing reads -- swapping only the matcher would leave it stale);
- its last RPTO request is re-applied against the new pattern (trust: false keeps
  intersecting);
- a passphrase change, a removed pattern or a blacklisting disconnects that one
  repeater only;
- a file that does not load changes nothing;
- sections read only at startup are reported, not applied.
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
from hblink4.access_control import RepeaterMatcher
from hblink4.constants import MSTCL
from hblink4.hblink import HBProtocol, reload_config
from hblink4.models import RepeaterState


def pattern(rid, passphrase, ts1, ts2):
    return {'name': f'hotspot-{rid}', 'description': '', 'match': {'ids': [rid]},
            'config': {'passphrase': passphrase, 'trust': False,
                       'slot1_talkgroups': ts1, 'slot2_talkgroups': ts2}}


BASE = {
    'global': {'user_cache': {'timeout': 600}, 'port_ipv4': 62031},
    'dashboard': {'enabled': False},
    'repeater_configurations': {'patterns': [
        pattern(302708301, 'pw-a', [3027], [3026, 302]),
        pattern(302708302, 'pw-b', [3027], [3026]),
        pattern(302708303, 'pw-c', [3027], [3100]),
    ]},
}


class FakeTransport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr=None):
        self.sent.append((data, addr))

    def to(self, addr):
        return [d for d, a in self.sent if a == addr]


def tgs(values):
    return {v.to_bytes(3, 'big') for v in values}


class ReloadTestCase(unittest.TestCase):
    def setUp(self):
        self._saved = hblink_mod.CONFIG
        hblink_mod.CONFIG = copy.deepcopy(BASE)
        hblink_mod.LOGGER = logging.getLogger('test-reload')
        self.hb = HBProtocol()
        self.hb.transport = self.hb._port = FakeTransport()
        self.addrs = {}
        for i, rid in enumerate((302708301, 302708302, 302708303)):
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

    def write(self, cfg):
        with open(self.file.name, 'w') as f:
            json.dump(cfg, f)

    def reload(self, cfg=None):
        if cfg is not None:
            self.write(cfg)
        return reload_config(self.file.name, [self.hb])

    def edited(self, changes):
        """BASE with some patterns replaced: {rid: (passphrase, ts1, ts2) or None}."""
        cfg = copy.deepcopy(BASE)
        pats = []
        for p in cfg['repeater_configurations']['patterns']:
            rid = p['match']['ids'][0]
            if rid in changes:
                if changes[rid] is None:
                    continue
                p = pattern(rid, *changes[rid])
            pats.append(p)
        cfg['repeater_configurations']['patterns'] = pats
        return cfg

    # -- talkgroups follow the new pattern, in place ---------------------------

    def test_a_talkgroup_change_reaches_the_connected_repeater(self):
        before_b = (self.rep(302708302).slot1_talkgroups, self.rep(302708302).slot2_talkgroups)
        self.assertTrue(self.reload(self.edited({302708301: ('pw-a', [3027], [3026, 302, 3100])})))
        self.assertEqual(self.rep(302708301).slot2_talkgroups, tgs([3026, 302, 3100]))
        self.assertEqual((self.rep(302708302).slot1_talkgroups, self.rep(302708302).slot2_talkgroups),
                         before_b)
        self.assertEqual(self.hb.transport.sent, [], 'a reload sent something to a repeater')
        self.assertEqual(len(self.hb._repeaters), 3)

    def test_the_repeaters_rpto_request_is_reapplied_against_the_new_pattern(self):
        a = self.rep(302708301)
        # It asked for 3026 and 3100 on TS2; the pattern allows 3026 and 302: gets 3026.
        self.hb._handle_options(a.repeater_id, b'TS1=3027;TS2=3026,3100', self.addrs[302708301])
        self.assertEqual(a.slot2_talkgroups, tgs([3026]))
        # 3100 is now allowed: its standing request picks it up without logging in again.
        self.reload(self.edited({302708301: ('pw-a', [3027], [3026, 302, 3100])}))
        self.assertEqual(a.slot2_talkgroups, tgs([3026, 3100]))
        self.assertIs(self.rep(302708301), a)

    def test_new_logins_use_the_new_pattern(self):
        self.reload(self.edited({302708303: ('pw-c', [3027], [3100, 91])}))
        cfg = self.hb._matcher.get_repeater_config(302708303, 'VE7KA')
        self.assertEqual(cfg.slot2_talkgroups, [3100, 91])

    # -- exactly one repeater disconnected ------------------------------------

    def test_a_passphrase_change_disconnects_only_that_repeater(self):
        self.reload(self.edited({302708302: ('new-pw', [3027], [3026])}))
        self.assertIsNone(self.rep(302708302))
        self.assertIsNotNone(self.rep(302708301))
        self.assertIsNotNone(self.rep(302708303))
        self.assertEqual(self.hb.transport.to(self.addrs[302708302]), [MSTCL])
        self.assertEqual(self.hb.transport.to(self.addrs[302708301]), [])

    def test_a_removed_pattern_disconnects_only_that_repeater(self):
        self.reload(self.edited({302708303: None}))
        self.assertIsNone(self.rep(302708303))
        self.assertEqual(len(self.hb._repeaters), 2)

    def test_a_blacklisted_id_is_disconnected(self):
        cfg = copy.deepcopy(BASE)
        cfg['blacklist'] = {'patterns': [{'name': 'x', 'description': '',
                                          'match': {'ids': [302708301]}, 'reason': 'abuse'}]}
        self.reload(cfg)
        self.assertIsNone(self.rep(302708301))
        self.assertEqual(len(self.hb._repeaters), 2)

    # -- nothing changes on a bad file ----------------------------------------

    def test_a_file_that_does_not_load_changes_nothing(self):
        matcher = self.hb._matcher
        with open(self.file.name, 'w') as f:
            f.write('{"repeater_configurations": {"patterns": [ broken')
        self.assertFalse(self.reload())
        self.assertIs(self.hb._matcher, matcher)
        self.assertEqual(len(self.hb._repeaters), 3)

    def test_a_pattern_that_does_not_validate_changes_nothing(self):
        cfg = copy.deepcopy(BASE)
        cfg['repeater_configurations']['patterns'].append(
            {'name': 'bad', 'match': {'ids': ['not-an-id']}, 'config': {'passphrase': 'x'}})
        matcher = self.hb._matcher
        self.assertFalse(self.reload(cfg))
        self.assertIs(self.hb._matcher, matcher)

    def test_startup_only_sections_are_reported_not_applied(self):
        cfg = copy.deepcopy(BASE)
        cfg['global']['port_ipv4'] = 62099
        with self.assertLogs('test-reload', level='WARNING') as logs:
            self.assertTrue(self.reload(cfg))
        self.assertTrue(any('global' in m and 'restart' in m for m in logs.output))
        self.assertEqual(hblink_mod.CONFIG['global']['port_ipv4'], 62031)


if __name__ == '__main__':
    unittest.main()
