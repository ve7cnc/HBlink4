"""
RF quality from a hotspot's DMRD: byte 53 (BER) and byte 54 (RSSI).

An MMDVM device puts the corrected-bit count of each voice burst (of 141 protected
bits) in byte 53 and the received signal strength, as a positive magnitude, in byte 54
(0 = not reported). Ported from alhedward/HBlink4 (2026-07-15, "Expose DMR BER and
RSSI in stream events").

What must hold:
- voice bursts are sampled, headers and terminators are not (their 0 is not a reading);
- an RSSI of 0 is no reading, never 0 dBm, and BER is still counted;
- stream_update and stream_end carry `rf_quality`; a stream with no samples carries none;
- stream_update carries the stream ID, so a listener can match it to its start;
- streams we send (assumed) never get a reading.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hblink4.models import StreamState
from hblink4.protocol import parse_dmr_packet
from tests.test_ptt_activation import A, B, PttTestCase, tg

SID = b'\x00\x00\x00\x2a'


def dmrd(bits, ber=0, rssi=0, seq=0, rid=A, dst=3027, sid=SID):
    return (b'DMRD' + bytes([seq]) + tg(3027083) + tg(dst) + rid.to_bytes(4, 'big')
            + bytes([bits]) + sid + bytes(33) + bytes([ber, rssi]))


HEAD, TERM = 0xA1, 0xA2          # TS2, data sync, voice header / terminator
VOICE = [0x90, 0x81, 0x82, 0x83, 0x84, 0x85]   # TS2, burst A (voice sync), then B-F


class Parse(PttTestCase):

    def test_ber_and_rssi_are_parsed(self):
        p = parse_dmr_packet(dmrd(VOICE[0], ber=3, rssi=71))
        self.assertEqual((p['ber_errors'], p['rssi_dbm']), (3, -71))

    def test_rssi_zero_is_no_reading(self):
        self.assertIsNone(parse_dmr_packet(dmrd(VOICE[0], ber=3, rssi=0))['rssi_dbm'])


class Stream(PttTestCase):

    def send(self, bits, **kw):
        self.hb._handle_dmr_data(dmrd(bits, **kw), self.addrs[kw.get('rid', A)])

    def call(self, bursts, rssi=0, ber=0):
        self.send(HEAD, ber=99, rssi=40)            # never a sample
        for i in range(bursts):
            self.send(VOICE[i % 6], seq=i + 1, ber=ber, rssi=rssi)
        self.send(TERM, seq=bursts + 1, ber=99, rssi=40)

    def ended(self):
        return [d for t, d in self.events if t == 'stream_end' and d.get('repeater_id') == A]

    def test_voice_bursts_are_summarised_at_the_end(self):
        self.send(HEAD, ber=99, rssi=40)
        for i, (ber, rssi) in enumerate([(0, 70), (3, 72), (6, 74)]):
            self.send(VOICE[i], seq=i + 1, ber=ber, rssi=rssi)
        self.send(TERM, seq=4, ber=99, rssi=40)
        q = self.ended()[0]['rf_quality']
        self.assertEqual(q, {
            'ber_average_percent': 2.13, 'ber_peak_percent': 4.26, 'ber_samples': 3,
            'rssi_average_dbm': -72.0, 'rssi_min_dbm': -74, 'rssi_max_dbm': -70,
            'rssi_samples': 3})

    def test_a_device_without_rssi_still_reports_ber(self):
        self.call(6, rssi=0, ber=1)
        q = self.ended()[0]['rf_quality']
        self.assertEqual(q['ber_samples'], 6)
        self.assertNotIn('rssi_average_dbm', q)

    def test_stream_update_carries_quality_and_stream_id(self):
        self.call(70, rssi=80, ber=0)
        ups = [d for t, d in self.events if t == 'stream_update']
        self.assertTrue(ups)
        self.assertEqual(ups[0]['stream_id'], SID.hex())
        self.assertEqual(ups[0]['rf_quality']['rssi_average_dbm'], -80.0)
        self.assertEqual(ups[0]['rf_quality']['ber_average_percent'], 0.0)

    def test_header_and_terminator_alone_give_no_quality(self):
        self.send(HEAD, ber=99, rssi=40)
        self.send(TERM, seq=1, ber=99, rssi=40)
        self.assertNotIn('rf_quality', self.ended()[0])

    def test_streams_we_send_get_no_reading(self):
        self.call(6, rssi=70, ber=2)
        tx = [d for t, d in self.events if t == 'stream_end' and d.get('repeater_id') == B]
        self.assertTrue(tx and all(d['is_assumed'] for d in tx))
        self.assertTrue(all('rf_quality' not in d for d in tx))


class Model(PttTestCase):

    def test_out_of_range_ber_is_ignored(self):
        s = StreamState(repeater_id=b'\0\0\0\1', rf_src=b'\0\0\1', dst_id=b'\0\0\1', slot=2,
                        start_time=0, last_seen=0, stream_id=SID)
        s.add_rf_sample(200, None)
        self.assertIsNone(s.rf_quality())
