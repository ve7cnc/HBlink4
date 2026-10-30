"""Private (unit-to-unit) calls over OpenBridge (our fork, 2026-10-30): off by default;
when on, an inbound one lands on unit_slot and fans out to local repeaters only, the
caller is cached as reachable through the trunk on its wire slot, local private calls
may go out over the trunk, and a reply goes back on the slot the caller used."""
from unittest.mock import Mock

import pytest

from hblink4 import config as C
from hblink4.hblink import HBProtocol
from hblink4.models import OpenBridgeConnectionConfig, OpenBridgeState
from hblink4.user_cache import UserCache

from tests.test_openbridge import _dmrd, _obp


def _unit_dmrd(dst, src=3027004, slot=1, sid=b'\x0a\x0b\x0c\x0d'):
    d = bytearray(_dmrd(dst, src=src, slot=slot, sid=sid))
    d[15] |= 0x40                                   # call type: private
    return bytes(d)


def _state(name='A', unit_calls=True, unit_slot=2):
    cfg = OpenBridgeConnectionConfig(
        enabled=True, name=name, network_id=3129900, local_address='0.0.0.0',
        local_port=1, target_address='x', target_port=1, passphrase='secret',
        talkgroup_slots={(3027).to_bytes(3, 'big'): 2},
        unit_calls=unit_calls, unit_slot=unit_slot)
    st = OpenBridgeState(config=cfg, ip='10.0.0.9', port=62035)
    st.transport = Mock()
    return st


def _protocol(*states):
    p = HBProtocol.__new__(HBProtocol)
    p._repeaters, p._outbounds = {}, {}
    p._openbridges = {s.config.name: s for s in states}
    p._events = Mock()
    p._user_cache = UserCache()
    return p


def test_config_defaults_off_and_parses():
    [o] = C.parse_openbridge_connections({'openbridge_connections': [_obp('A', {'31': '1'})]})
    assert o.unit_calls is False and o.unit_slot == 2
    raw = dict(_obp('A', {'31': '1'}), unit_calls=True, unit_slot=1)
    [o] = C.parse_openbridge_connections({'openbridge_connections': [raw]})
    assert o.unit_calls is True and o.unit_slot == 1
    with pytest.raises(SystemExit):
        C.parse_openbridge_connections({'openbridge_connections': [
            dict(_obp('A', {'31': '1'}), unit_slot=3)]})


def test_inbound_private_call_dropped_when_off():
    st = _state(unit_calls=False)
    p = _protocol(st)
    forwarded = []
    p._forward_stream = lambda *a, **k: forwarded.append(a)
    frame = p._obp_build_egress(st, _unit_dmrd(3021234), (302145).to_bytes(4, 'big'))
    p._handle_openbridge_packet('A', frame, ('10.0.0.9', 62035))
    assert not forwarded and not st.streams


def test_inbound_private_call_lands_on_unit_slot_and_caches_the_caller():
    st = _state()
    p = _protocol(st)
    forwarded = []
    p._forward_stream = lambda *a, **k: forwarded.append(a)
    frame = p._obp_build_egress(st, _unit_dmrd(3021234, src=3027004),
                                (302145).to_bytes(4, 'big'), wire_slot=1)
    p._handle_openbridge_packet('A', frame, ('10.0.0.9', 62035))
    [stream] = st.streams.values()
    assert stream.is_unit_call and stream.call_type == 'private' and stream.slot == 2
    assert not any(isinstance(t, tuple) for t in stream.target_repeaters)   # never back out
    data, source, slot = forwarded[0][:3]
    assert source == ('openbridge', 'A') and slot == 2 and data[15] & 0x80
    entry = p._user_cache.lookup(3027004)
    assert entry.openbridge_name == 'A' and entry.slot == 1
    assert p._events.emit.call_args.args[1]['call_type'] == 'private'


def test_local_private_calls_may_go_out_over_a_unit_trunk():
    on, off = _state('A'), _state('B', unit_calls=False)
    p = _protocol(on, off)
    targets, broadcast = p._calculate_unit_call_targets(
        (3020485).to_bytes(4, 'big'), 2, (3020485).to_bytes(3, 'big'),
        (3027004).to_bytes(3, 'big'), b'\x01\x02\x03\x04')
    assert broadcast and ('openbridge', 'A') in targets and ('openbridge', 'B') not in targets
    # Heard through the trunk: one-to-one back over it.
    p._user_cache.update(radio_id=3027004, repeater_id=0, callsign='', slot=1,
                         talkgroup=3020485, openbridge_name='A')
    targets, broadcast = p._calculate_unit_call_targets(
        (3020485).to_bytes(4, 'big'), 2, (3020485).to_bytes(3, 'big'),
        (3027004).to_bytes(3, 'big'), b'\x01\x02\x03\x05')
    assert not broadcast and targets == {('openbridge', 'A')}


def test_a_reply_goes_back_on_the_callers_wire_slot():
    st = _state()
    p = _protocol(st)
    dst = (3027004).to_bytes(3, 'big')
    assert p._obp_unit_wire_slot('A', dst, 2) == 2              # unknown: its own slot
    p._user_cache.update(radio_id=3027004, repeater_id=0, callsign='', slot=1,
                         talkgroup=3020485, openbridge_name='A')
    assert p._obp_unit_wire_slot('A', dst, 2) == 1              # the caller's slot there
    assert p._obp_unit_wire_slot('B', dst, 2) == 2              # another trunk: no
    d = p._obp_build_egress(st, _unit_dmrd(3027004, slot=2), (3020485).to_bytes(4, 'big'),
                            wire_slot=2)[:53]
    assert d[15] & 0x80 and d[15] & 0x40                        # slot 2, still private
    g = p._obp_build_egress(st, _dmrd(3027, slot=2), (3020485).to_bytes(4, 'big'))[:53]
    assert not g[15] & 0x80                                      # group: slot 1, as before


def test_without_flood_an_unheard_radio_is_never_flooded_to_local_repeaters(monkeypatch):
    import hblink4.hblink as H
    monkeypatch.setitem(H.CONFIG, 'global', {**H.CONFIG.get('global', {}), 'unit_call_flood': False})
    st = _state('A')
    p = _protocol(st)
    local = Mock(connection_state='connected', unit_calls_enabled=True)
    p._repeaters = {(3020485).to_bytes(4, 'big'): local, (3021111).to_bytes(4, 'big'): local}
    p._is_slot_busy = lambda *a, **k: False
    # From a hotspot: only up the trunk, where the cores know where it was heard.
    targets, broadcast = p._calculate_unit_call_targets(
        (3020485).to_bytes(4, 'big'), 2, (3020485).to_bytes(3, 'big'),
        (3027999).to_bytes(3, 'big'), b'\x01\x02\x03\x06')
    assert targets == {('openbridge', 'A')}
    # From the trunk: nowhere.
    targets, _ = p._calculate_unit_call_targets(
        None, 2, (3027004).to_bytes(3, 'big'), (3027999).to_bytes(3, 'big'),
        b'\x01\x02\x03\x07', source_openbridge_name='A')
    assert targets == set()
    # A radio heard on a hotspot still goes straight there.
    p._user_cache.update(radio_id=3027999, repeater_id=3021111, callsign='', slot=2,
                         talkgroup=3027)
    targets, broadcast = p._calculate_unit_call_targets(
        None, 2, (3027004).to_bytes(3, 'big'), (3027999).to_bytes(3, 'big'),
        b'\x01\x02\x03\x08', source_openbridge_name='A')
    assert targets == {(3021111).to_bytes(4, 'big')} and not broadcast
