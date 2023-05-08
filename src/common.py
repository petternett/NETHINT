from scapy.all import conf, Dot11, get_if_addr

# --- Main program arguments --- #

# Interface
use_iface = None
def set_iface(ifs):
    global use_iface
    use_iface = ifs

def get_iface():
    return use_iface

# SSID
ssid    = None
ssid_mac_list = []
def set_ssid(s: str) -> None:
    global ssid
    ssid = s if s is not None else '*'

def get_ssid() -> str:
    return ssid

def add_mac(new_mac: str) -> None:
    if ssid != '*': ssid_mac_list.append(new_mac)

""" Check if address is associated with SSID,
    or we check packets associated with ANY SSID.
"""
def is_valid_ssid(addr: str) -> bool:
    return addr in ssid_mac_list or ssid == '*'


# Output to STDOUT
# Future: output levels? 0 (default): info, 1: verbose, 2: debug, etc...
output = False
def set_output(val: bool=False) -> None:
    global output
    output = val

def get_output():
    return output


# Relative time
relative_time = False
time_base = None
def set_relative_time(arg: bool=True) -> None:
    global relative_time
    relative_time = arg

def isset_relative_time() -> bool:
    return relative_time

def set_time_base(time: int) -> None:
    global time_base
    time_base = time

def get_time_base() -> int | None:
    return time_base


# Emulated / local NIC / wireless mode
mode: str = ""
def set_mode(arg: str='wireless') -> None:
    global mode
    mode = arg

def check_mode() -> str:
    return mode

# Emulated mode IP list
def emulated_ip_list() -> [str]:
    return ['10.1.3.100',
            '10.1.4.100',
            '10.2.1.100',
            '10.2.2.100']


# GUI
gui_enabled = False
def set_gui(arg: bool=True) -> None:
    global gui_enabled
    gui_enabled = arg

def isset_gui() -> bool:
    return gui_enabled


# Logging
log_enabled = False
def set_log(arg: bool=True) -> None:
    global log_enabled
    log_enabled = arg

def isset_log() -> bool:
    return log_enabled


# Write PCAP file
write_pcap_file = None
def set_write_pcap(fp: str):
    global write_pcap_file
    write_pcap_file = fp

def get_write_pcap():
    return write_pcap_file

# --- Helpers --- #
""" Print without line break."""
def printn(string) -> None:
    print(string, end='')


""" Compare addresses.

Return True if A has higher string value than B.
If addresses are equal, return True if A has largest port number.
"""
def cmp_address(addr_a, port_a, addr_b, port_b) -> bool:
    return addr_a > addr_b if addr_a != addr_b else port_a > port_b

""" Check if a packet pkt is from local. Used to check for outgoing packets.
    Note that this is not the same as the flow direction, which is arbitrary.
    This function checks whether a packet went from a local to a remote device for all modes.

    Modes:
      - Local WNIC mode: dest IP is not same as interface (default=WNIC).
      - Wireless mode: dest MAC address is a known AP. Works since we already know
                       from process_packet() that either the src or dest is an AP.
      - Emulated mode: dest IP address is going to a known IP of a sender.

    @return: True if packet was sent from a local device, False otherwise.
"""
def check_from_local(pkt) -> bool:

    match check_mode():
        case "local":
            return pkt.ip_dst != get_if_addr(get_iface())
        case "wireless":
            return (pkt.pkt.haslayer(Dot11)
                    and is_valid_ssid(pkt.pkt.addr1))
        case "emulated":
            return pkt.ip_dst in emulated_ip_list()


""" Check if a packet pkt is to local. Used to check for incoming packets. """
def check_to_local(pkt) -> bool:

    match check_mode():
        case "local":
            return pkt.ip_src != get_if_addr(get_iface())
        case "wireless":
            return (pkt.pkt.haslayer(Dot11)
                    and is_valid_ssid(pkt.pkt.addr2))
        case "emulated":
            return pkt.ip_src in emulated_ip_list()
