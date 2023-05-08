from scapy.fields import *
from scapy.packet import Packet

""" Extension of Scapy to handle QUIC packets.
    Automatically interprets any UDP packets with
    source or destination port set to 443 as a QUIC packet
    (defined in QUICPacket.py).
"""
LONG_HEADER_FORM = 1
SHORT_HEADER_FORM = 0
class QUIC(Packet):
    name = "QUIC"

    # TODO: Incomplete, but it checks the packet type,
    #       which is what matters for checking the initial/handshake packets.
    # Also it checks the spin bit in case that is enabled.
    fields_desc = [
        BitField("header_form", 0, 1),
        BitField("fixed_bit", 0, 1),
        ConditionalField(
            BitField("long_packet_type", 0, 2),
            lambda pkt: (pkt.header_form == LONG_HEADER_FORM
                         and pkt.fixed_bit == 1),
        ),
        ConditionalField(
            BitField("spin_bit", 0, 1),
            lambda pkt: (pkt.header_form == SHORT_HEADER_FORM
                         and pkt.fixed_bit == 1),
        ),
        StrFixedLenField("Version", "", 4),
    ]
