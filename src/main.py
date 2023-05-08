from scapy.all import sniff, conf, Packet, UDP, get_if_list
from QUIC import QUIC
import argparse
from datetime import datetime
import sys

from packet_dissect import process_packet
from common import (
        printn,
        set_ssid,
        get_ssid,
        set_output,
        get_output,
        set_relative_time,
        set_mode,
        set_log,
        set_gui,
        set_iface,
        get_iface,
        set_write_pcap,
    )
from gui import init_plot_obj
#from db_helpers import get_db
from logger import start_logger

#DB_NAME = "pkt_db"
read_pcap_file = None

def parse_args():
    """Parse argmuents and select an interface to listen on.

    If -ls is set, list interfaces and exit.
    If no interface is selected, choose default one.
    """
    global read_pcap_file

    parser = argparse.ArgumentParser(description="Process input arguments")
    parser.add_argument(
            "-ls",
            "--list-interfaces",
            action="store_true",
            help="list available network interfaces"
        )
    parser.add_argument(
            "interface",
            action="store",
            type=int,
            nargs='?',
            help="select interface by index"
        )
    parser.add_argument(
            "-r",
            "--read-pcap",
            action="store",
            type=str,
            nargs='?',
            help="read pcap file instead of from interface"
        )
    parser.add_argument(
            "-w",
            "--write-pcap",
            action="store",
            type=str,
            nargs='?',
            help="write pcap file"
        )
    parser.add_argument(
            "-s",
            "--ssid",
            action="store",
            type=str,
            nargs='?',
            help="select SSID to listen to"
        )
    parser.add_argument(
            "-o",
            "--output",
            action="store_true",
            help="output packet capture to STDOUT"
        )
    parser.add_argument(
            "-g",
            "--gui",
            action="store_true",
            help="enable GUI"
        )
    parser.add_argument(
            "-l",
            "--log",
            action="store",
            type=str,
            nargs='?',
            metavar="FILE",
            const=f"{datetime.now().strftime('%Y-%m-%d-%H:%M:%S')}.json",
            help="enable logging to [FILE]. Generates filename if not specified."
        )
    parser.add_argument(
            "-t",
            "--relative-time",
            action="store_true",
            help="display relative time in output(s)"
        )

    """ Select a mode.
        - Wireless: Packets were captured in monitor mode, and have 802.11 headers.
                    Each point in the GUI represents all the flows of one device on the WLAN.

        - Local:    Packets were captured on the local NIC.
                    Each point in the GUI represents one flow's destination address.

        - Emulated: Packets were emulated and have fixed IP addresses.
                    Each point in the GUI represents one flow's destination address.
    """
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--wireless", action="store_const", dest="mode", const='wireless', help="(default) packets were captured in wireless monitor mode and have 802.11 headers")
    mode_group.add_argument("--local",    action="store_const", dest="mode", const='local', help="packets were captured on local NIC")
    mode_group.add_argument("--emulated", action="store_const", dest="mode", const='emulated', help="packets were emulated and have fixed IPs")

    args = parser.parse_args()
    # TODO: see all flows mode, just change flow_key in GUI to ip:port>ip:port instead of mac>mac.
    #       also that is good future work, GUI could be able to select one device and look closely at all flows. framework is there.

    # -ls flag set, list interfaces and exit
    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    # -r flag set, read pcap file
    if args.read_pcap:
        read_pcap_file = args.read_pcap

    select_interface(args.interface)

    # -w flag set, write pcap file
    if args.write_pcap:
        set_write_pcap(args.write_pcap)

    # -t flag set, use relative time
    if args.relative_time:
        set_relative_time()

    # mode selection
    print(f"Selected mode: {args.mode}")
    set_mode(args.mode)

    # Select SSID (any(*) if -s not set)
    set_ssid(args.ssid)
    if (args.mode == "wireless"):
        printn(f"Listening to SSID: {get_ssid()}")
        print(" (any)" if args.ssid is None else "")


    # Output packet capture to STDOUT (False if -o not set)
    set_output(args.output)
    print(f"Printing packet capture: {get_output()}")

    # Enable/disable GUI
    if args.gui:
        # Initialize plot object reference
        init_plot_obj()

    set_gui(args.gui)

    # Enable/disable logging
    if args.log is not None:
        set_log(True)
        print(f"Enabled logging to \"{args.log}\"")
        start_logger(args.log)


def list_interfaces():
    for i, c_if in enumerate(get_if_list()):
        printn(f"{i}: {c_if}")
        if c_if == conf.iface:
            printn(" (default)")
        print()


def select_interface(if_idx):
    # set in common, read in check_pkt_local from loca l whatee

    if if_idx is None:
        # fallback to default interface
        set_iface(conf.iface)
        print(f"Set interface to {conf.iface}")
        return

    # interface index is specified
    if_list = get_if_list()

    if if_idx > len(if_list)-1:
        print(f"Interface {if_idx} is not in list:")
        list_interfaces()
        sys.exit(1)

    sel_if = if_list[if_idx]
    set_iface(sel_if)
    print(f"Selected interface {get_iface()}")



if __name__ == "__main__":
    # parse arguments and select interface
    parse_args()

    # connect to database
    # db = get_db(DB_NAME)

    if read_pcap_file:
        sniff(prn=process_packet, offline=read_pcap_file)
    else:
        sniff(prn=process_packet, iface=get_iface())
    # print(cap.summary())
