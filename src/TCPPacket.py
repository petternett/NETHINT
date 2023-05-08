from scapy.all import TCP
from common import (
        cmp_address,
        get_output,
        is_valid_ssid,
        check_mode,
        emulated_ip_list,
        check_from_local,
        check_to_local,
    )
from connection import find_connection

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80
NS  = 0x100


class TCPPacket:

    def __init__(self, pkt, ip_ver):

        # --- Parse --- #
        self.cap_time = float(pkt.time) # in µs since epoch
        self.rtt = None
        self.owd_diff = None

        # Parse IP header
        self.ip_src = pkt[ip_ver].src
        self.ip_dst = pkt[ip_ver].dst
        self.port_a = pkt[TCP].sport
        self.port_b = pkt[TCP].dport

        self.is_lost = False

        self.con = find_connection(self.ip_src, self.port_a, self.ip_dst, self.port_b)
        direction = cmp_address(self.ip_src, self.port_a, self.ip_dst, self.port_b)

        self.flow_direction = None
        if direction:  # A > B
            self.flow_direction = self.con.fwd
        else:
            self.flow_direction = self.con.rev

        if self.flow_direction is None:  # Error
            return

        # Connection ID, Flow ID
        self.cid = self.con.cid
        self.fid = self.flow_direction.fid

        # Parse TCP header
        self.seq      = pkt[TCP].seq
        self.ack      = pkt[TCP].ack
        self.window   = pkt[TCP].window
        self.flags    = pkt[TCP].flags.value
        self.options  = pkt[TCP].options
        self.seg_len  = len(pkt[TCP].payload)
        self.next_seq = self.seq + self.seg_len
        if self.flags & (SYN | FIN) > 0: self.next_seq += 1

        # Remove payload (not needed after setting self.seg_len)
        pkt[TCP].remove_payload()

        # Save Scapy packet header for processing in common.py and such
        self.pkt = pkt

        # Parse timestamps if supported
        self.tsval = 0
        self.tsecr = 0
        self.ts = next((opt for opt in self.options if opt[0] == "Timestamp"), None)
        if self.ts:
            self.tsval = self.ts[1][0]
            if (self.flags & ACK) > 0:  # TSecr is only valid if ACK flag is set
                self.tsecr = self.ts[1][1]

        # Debug
        if get_output() and self.ts and self.flow_direction.tsval:
            print(f"TSval: {self.tsval}, TSecr: {self.tsecr}.\
                    Time since prev: {self.tsval-self.flow_direction.tsval}ms")


        # --- Analyze --- #
        self.analyze_packet()

        # --- Find OWD of timestamp-enabled packets --- #
        self.check_owd()

        # --- Find RTT --- #
        self.rtt = self.find_rtt()

        # --- Update flow --- #
        self.update_flow()


    def analyze_packet(self) -> None:

        # Zero window probe
        self.is_zero_window_probe = False
        if (self.seg_len == 1
                and self.seq == self.flow_direction.next_seq
                and self.flow_direction.rev.window == 0):

            if get_output(): print("TCP Zero window probe")
            self.is_zero_window_probe = True

            self.complete_analysis()
            return

        # Zero window
        self.is_zero_window = False
        if (self.window == 0 and (self.flags & (RST | FIN | SYN) == 0)):

            if get_output(): print("TCP Zero window")
            self.is_zero_window = True

        # Lost packet
        self.is_lost = False
        if (self.flow_direction.next_seq
                and self.seq > self.flow_direction.next_seq
                and self.flags & RST == 0):

            if get_output(): print("TCP Previous segment not captured")
            self.is_lost = True

        # Keep-Alive packet (supersedes retransmission)
        self.is_keepalive = False
        if ((self.seg_len == 0 or self.seg_len == 1)
                and self.seq == self.flow_direction.next_seq-1
                and (self.flags & (FIN | SYN | RST)) == 0):

            if get_output(): print("TCP Keep-Alive")
            self.is_keepalive = True

            self.complete_analysis()
            return

        # Window update
        self.is_window_update = False
        if (self.seg_len == 0
                and self.window
                and self.window != self.flow_direction.window
                and self.seq == self.flow_direction.next_seq
                and self.ack == self.flow_direction.last_ack
                and self.flags & (SYN | FIN | RST) == 0):

            if get_output(): print("TCP Window update")
            self.is_window_update = True

        # TODO Window full? (pretty complicated)

        # Keep-Alive self.ack (supersedes DupACK)
        self.is_keepalive_ack = False
        if (self.seg_len == 0
                and self.window
                and self.window == self.flow_direction.window
                and self.seq == self.flow_direction.next_seq
                and self.ack == self.flow_direction.last_ack
                and self.flow_direction.rev.get_prev_pkt()
                and self.flow_direction.rev.get_prev_pkt().is_keepalive
                and (self.flags & (FIN | SYN | RST)) == 0):

            if get_output(): print("TCP Keep-Alive ACK")
            self.is_keepalive_ack = True

            self.complete_analysis()
            return

        # Zero window probe ACK
        self.is_zero_probe_ack = False
        if (self.seg_len == 0
                and self.window == 0
                and self.window == self.flow_direction.window
                and self.seq == self.flow_direction.next_seq
                and self.ack == self.flow_direction.last_ack
                and self.flow_direction.rev.get_prev_pkt()
                and self.flow_direction.rev.get_prev_pkt().is_zero_window_probe
                and (self.flags & (SYN | FIN | RST) == 0)):

            if get_output(): print("TCP Zero window probe ACK")
            self.is_zero_probe_ack = True

            self.complete_analysis()
            return

        # DupACK
        self.is_dupack = False
        if (self.seg_len == 0
                and self.window
                and self.window == self.flow_direction.window
                and self.seq == self.flow_direction.next_seq
                and self.ack == self.flow_direction.last_ack
                and (self.flags & (FIN | SYN | RST) == 0)):

            self.is_dupack = True
            if get_output(): print("TCP DupACK")


        # --- Complete analysis --- #
        self.complete_analysis()


    def complete_analysis(self):

        # ACKed lost packet
        self.is_acked_lost = False
        if (self.flow_direction.rev.max_to_ack
                and self.ack > self.flow_direction.rev.max_to_ack
                and (self.flags & (ACK) != 0)):

            if self.flow_direction.rev.max_to_ack < self.flow_direction.rev.next_seq:
                self.flow_direction.rev.max_to_ack = self.flow_direction.rev.next_seq

            # TODO check for stalled pure ACKs in reverse direction (wireshark tcp.c)

            self.is_acked_lost = True


        # TCP Restransmission (omitting fast retransmission / out-of-order checks)
        self.is_retransmission = False
        if ((self.seg_len > 0 or self.flags & (SYN | FIN) == 0)
                and self.flow_direction.next_seq
                and self.seq < self.flow_direction.next_seq
                and not self.is_keepalive):

            self.is_retransmission = True
            if get_output(): print("TCP Retransmission")

    
    """ Check RTT of SYN packets.
        The first SYN packet determines whether a TCP connection is outgoing or incoming.
        Return RTT if check_pkt (SYN + maybe ACK) was from local.
    """
    # TODO duplicate code. merge into one, check pkt_type == SYN or pkt_type == FIN
    def check_syn(self) -> int | None:

        # Previous packet was SYN, current packet is ACK
        check_pkt = self.flow_direction.rev.pair_pkts.get(self.ack, False)
        if ((self.flags & ACK) > 0
                and check_pkt
                and (check_pkt.flags & SYN)
                and check_from_local(check_pkt)):

            # Discard retransmitted packets
            if self.is_retransmission or check_pkt.is_retransmission:
                self.con.syn_found = True
                return None
            
            self.con.syn_found = True
            rtt = (self.cap_time - check_pkt.cap_time) * 1000
            if get_output(): print(f"SYN packet pairing found RTT of {rtt} ms.")
            return rtt


    """ FIN packets.
        The first FIN packet determines who initiated the connection termination.
        Return RTT if check_pkt (FIN + maybe ACK) was from local.
    """
    def check_fin(self) -> int | None:

        # Previous packet was FIN, current packet is ACK
        check_pkt = self.flow_direction.rev.pair_pkts.get(self.ack, False)
        if ((self.flags & ACK) > 0
                and check_pkt
                and (check_pkt.flags & FIN) > 0
                and check_from_local(check_pkt)):

            # Discard retransmitted packets
            if self.is_retransmission or check_pkt.is_retransmission:
                self.con.fin_found = True
                return None

            self.con.fin_found = True
            rtt = (self.cap_time - check_pkt.cap_time) * 1000
            if get_output(): print(f"SYN packet pairing found RTT of {rtt} ms.")
            return rtt


    """ Normal packet pairing explained line-by-line:

        Current packet is an ACK, and
        matching packet in reverse direction exists, and
        Don't check the same TS twice.
          If not TS-packet: don't check same ACK twice,
                            and don't count retransmisions.
        Checked pkt was sent from a/the local device:
    """
    def do_packet_pairing(self) -> int | None:
        pair_pkt_key = self.tsecr if self.ts else self.ack
        check_pkt = self.flow_direction.rev.pair_pkts.get(pair_pkt_key, False)
        if ((self.flags & ACK) > 0
                and check_pkt
                and check_from_local(check_pkt)
                and ((self.ts and self.tsecr != self.flow_direction.tsecr)
                     or (not self.ts
                         and self.ack != self.flow_direction.last_ack
                         and not check_pkt.is_retransmission))):

            rtt = (self.cap_time - check_pkt.cap_time) * 1000
            if rtt > 1000:
                return None
            if get_output():
                print(f"Found valid RTT of {self.ip_src}>{self.ip_dst}: {rtt} ms.")
            
            del self.flow_direction.rev.pair_pkts[pair_pkt_key]
            return rtt


    """ Check OWD of TS-enabled incoming packets """
    def check_owd(self) -> None:
        prev_pkt = self.flow_direction.get_prev_pkt()
        if (self.ts
                and prev_pkt
                and check_to_local(self)
                and check_to_local(prev_pkt)):

            # NOTE: Relative to first measured OWD in flow
            owd = self.cap_time - self.tsval
            # if self.flow_direction.owd_base is None:
            #     self.flow_direction.owd_base = owd
            # self.owd_diff = owd - self.flow_direction.owd_base

            # NOTE: Relative to previous OWD measurement in flow
            if self.flow_direction.owd is None:
                self.flow_direction.owd = owd
                self.owd_diff = 0
                return

            _owd_diff = owd - self.flow_direction.owd
            if abs(_owd_diff) < 1000:
                self.owd_diff = _owd_diff
            if get_output(): print(f"OWD difference from previous: {_owd_diff}")
            self.flow_direction.owd = owd


    # TODO: remove key (del pair_pkts[key]) from pair_pkts after one pairing?
    def find_rtt(self) -> int | None:

        # Find closest packet pair and calculate capture time RTT
        rtt = None

        # Check SYN and FIN packets if not already found RTT from them
        if not self.con.syn_found:
            if rtt := self.check_syn(): return rtt
        if not self.con.fin_found:
            if rtt := self.check_fin(): return rtt

        # Normal Timestamp or SEQ/ACK packet pairing
        if rtt := self.do_packet_pairing(): return rtt


    def update_flow(self) -> None:

        # Update next_seq in Flow object to greatest seen SEQ number
        if (self.next_seq > self.flow_direction.next_seq or not self.flow_direction.next_seq):
            self.flow_direction.next_seq = self.next_seq

        # Update max sequence number to be ACKed to detect is_acked_lost
        if (self.seq == self.flow_direction.max_to_ack or not self.flow_direction.max_to_ack):
            if not self.is_zero_window_probe:
                self.flow_direction.max_to_ack = self.flow_direction.next_seq

        # Update last ACK and window
        self.flow_direction.last_ack = self.ack
        self.flow_direction.window   = self.window

        # Update Timestamps
        self.flow_direction.tsval = self.tsval
        self.flow_direction.tsecr = self.tsecr
        self.flow_direction.cap_time = self.cap_time
        self.flow_direction.rtt = self.rtt

        # Add TSval to flow timestamp dictionary.
        # If timestamps not enabled, fallback to SEQ/ACK.
        # Only add packets with data (segment length > 0)
        # For non-TS packets, we want to add the last one each time.
        # (skips the "exists in flow" check that TS packets do)

        # SYN, SYN/ACK, FIN or FIN/ACK packets are always added
        if (self.flags & (SYN|FIN)) > 0:
            self.flow_direction.pair_pkts[self.next_seq] = self

        else:
            # Timestamps enabled
            if self.ts:
                if (self.tsval not in self.flow_direction.pair_pkts
                        and self.seg_len > 0):
                    self.flow_direction.pair_pkts[self.tsval] = self

            # Fallback to SEQ/ACK
            else:
                self.flow_direction.pair_pkts[self.next_seq] = self


        # Add packet to flow
        self.flow_direction.add_pkt(self)

        # TODO: Store old packets in DB, not memory
        # TODO: Periodically delete old flows and connections
