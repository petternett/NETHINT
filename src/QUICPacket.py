from scapy.all import UDP
from QUIC import QUIC
from common import (
        printn,
        cmp_address,
        check_mode,
        is_valid_ssid,
        emulated_ip_list,
        check_from_local,
        get_output,
    )
from connection import find_connection

INITIAL = 0
HANDSHAKE = 2

class QUICPacket():
    def __init__(self, pkt, ip_ver):

        # --- Parse --- #
        self.pkt = pkt
        self.cap_time = float(pkt.time) # in µs since epoch

        self.ip_src = pkt[ip_ver].src
        self.ip_dst = pkt[ip_ver].dst
        self.port_a = pkt[UDP].sport
        self.port_b = pkt[UDP].dport

        self.con = find_connection(self.ip_src, self.port_a, self.ip_dst, self.port_b)
        direction = cmp_address(self.ip_src, self.port_a, self.ip_dst, self.port_b)

        self.flow_direction = None
        if (direction):  # A > B 
            self.flow_direction = self.con.fwd
        else:
            self.flow_direction = self.con.rev
        
        if self.flow_direction is None:  # Error
            return

        # Connection ID, Flow ID
        self.cid = self.con.cid
        self.fid = self.flow_direction.fid

        # QUIC parameters
        self.quic_type = None
        self.header_form = self.pkt[QUIC].header_form
        self.quic_type = self.pkt[QUIC].long_packet_type
        self.spin_bit  = self.pkt[QUIC].spin_bit
        if self.header_form == 1 and self.spin_bit == 1:
            self.flow_direction.spin_enabled = True

        self.rtt = self.find_rtt()

        # --- Update flow --- #
        self.update_flow()


    # Return RTT from QUIC handshake
    def find_rtt(self) -> int | None:

        check_pkt = self.flow_direction.rev.get_prev_pkt()
        if (self.quic_type == INITIAL
                and check_pkt
                and check_pkt.quic_type == INITIAL
                and check_from_local(check_pkt)):
            rtt = (self.cap_time - check_pkt.cap_time) * 1000
            if get_output(): print(f"RTT (initial): {rtt} ms")
            return rtt

        # Not necessarily enabled, just a short header
        if (self.spin_bit
                and check_pkt
                and check_pkt.spin_bit != self.spin_bit):
            rtt = (self.cap_time - check_pkt.cap_time) * 1000
            if get_output(): print(f"RTT (spin bit): {rtt} ms")
            return rtt

        return None


    def update_flow(self) -> None:
        self.flow_direction.cap_time = self.cap_time
        self.flow_direction.rtt = self.rtt

        # Add initial packets. If spin is enabled for the flow, add all packets.
        if self.quic_type == INITIAL or self.flow_direction.spin_enabled:
            self.flow_direction.add_pkt(self)
