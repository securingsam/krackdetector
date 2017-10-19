#!/usr/bin/env python
import os
import sys
import socket
import struct
import ctypes
import subprocess
from optparse import OptionParser

usage = "usage: %prog INTERFACE"

# Capture only EAPOL packets (Ethernet type 0x888e)
#     ldh   [12]
#     jeq   #0x800  jt 2    jf 3
#     ret   #0x0040000
#     ret   #0
eapol_filter = \
    [struct.pack('HBBI', 0x28, 0, 0, 0x0000000c),
     struct.pack('HBBI', 0x15, 0, 1, 0x0000888e),
     struct.pack('HBBI', 0x06, 0, 0, 0x00040000),
     struct.pack('HBBI', 0x06, 0, 0, 0x00000000)]

# Defined in asm-generic/socket.h
SO_ATTACH_FILTER = 26

# Defined in linux/if_ether.h
ETH_P_ALL = 0x0003
ETH_P_PAE = 0x888e

# Defined in eapol_common.h in wpa_supplicant
IEEE802_1X_TYPE_EAPOL_KEY = 3
# Defined in wpa_common.h in wpa_supplicant
WPA_KEY_INFO_KEY_TYPE = 1 << 3
WPA_KEY_INFO_INSTALL  = 1 << 6
WPA_KEY_INFO_ACK      = 1 << 7
WPA_KEY_INFO_MIC      = 1 << 8

ETHERNET_STRUCT = '>6s6sH'
ETHERNET_STRUCT_SIZE = struct.calcsize(ETHERNET_STRUCT)
IEEE802_1X_STRUCT = '>BBH'
IEEE802_1X_STRUCT_SIZE = struct.calcsize(IEEE802_1X_STRUCT)
WPA_KEY_STRUCT = '>BHHQ32s'
WPA_KEY_STRUCT_SIZE = struct.calcsize(WPA_KEY_STRUCT)

EAPOL_PKT_MIN_SIZE = ETHERNET_STRUCT_SIZE + \
                     IEEE802_1X_STRUCT_SIZE + \
                     WPA_KEY_STRUCT_SIZE

class KRACKDetector(object):
    def __init__(self, iface, dry_run):
        self.iface = iface
        self.dry_run = dry_run
        self.nonces = []
        self.sock = self._create_socket()

    def _create_socket(self):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        bpf = ctypes.create_string_buffer(''.join(eapol_filter))
        prog = struct.pack('HL', len(eapol_filter), ctypes.addressof(bpf))
        sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, prog)
        sock.bind((self.iface, ETH_P_ALL))
        return sock

    def _disassociate(self, mac):
        args = ['hostapd_cli', '-i', self.iface, 'disassociate', mac]
        try:
            output = subprocess.check_output(args)
            if "OK" not in output:
                print "hostapd_cli failed: %s" % output
            else:
                print '%s disassociated' % mac
        except subprocess.CalledProcessError:
            print "hostapd_cli failed"

    def _deauthenticate(self, mac):
        args = ['hostapd_cli', '-i', self.iface, 'deauthenticate', mac]
        try:
            output = subprocess.check_output(args)
            if "OK" not in output:
                print "hostapd_cli failed: %s" % output
            else:
                print '%s deauthenticated' % mac
        except subprocess.CalledProcessError:
            print "hostapd_cli failed"

    def _process_eapol_packet(self, pkt):
        if len(pkt) < EAPOL_PKT_MIN_SIZE:
            return

        # Extract Ethernet layer
        eth = pkt[:ETHERNET_STRUCT_SIZE]
        pkt = pkt[ETHERNET_STRUCT_SIZE:]
        dst_mac, src_mac, eth_type = struct.unpack('>6s6sH', eth)
        if eth_type != ETH_P_PAE:
            return

        # Extract IEEE802.1x header
        ieee802_1x = pkt[:IEEE802_1X_STRUCT_SIZE]
        pkt = pkt[IEEE802_1X_STRUCT_SIZE:]
        ver, pkt_type, pkt_len = struct.unpack('>BBH', ieee802_1x)
        if pkt_type != IEEE802_1X_TYPE_EAPOL_KEY:
            return

        # Extract WPA key data
        wpa_key = pkt[:WPA_KEY_STRUCT_SIZE]
        key_type, key_info, key_len, key_replay, key_nonce = \
            struct.unpack('>BHHQ32s', wpa_key)

        if key_info & WPA_KEY_INFO_KEY_TYPE:
            if key_info & WPA_KEY_INFO_INSTALL and \
               key_info & WPA_KEY_INFO_ACK and \
               key_info & WPA_KEY_INFO_MIC:
                sta = ':'.join(map(lambda x: x.encode('hex'), dst_mac))
                print 'Detected packet 3/4 to %s, nonce %s' % (sta, key_nonce.encode('hex'))
                if key_nonce in self.nonces:
                    print 'Detected duplicate packet 3!'
                    if not self.dry_run:
                        self._disassociate(sta)
                        self._deauthenticate(sta)
                else:
                    self.nonces.append(key_nonce)

    def detect(self):
        while True:
            pkt, addr = self.sock.recvfrom(1024)
            self._process_eapol_packet(pkt)

def main():
    parser = OptionParser(usage)
    parser.add_option("-n", "--dry-run", dest="dry_run",
                      action="store_true", help="Do not disconnect suspected devices")
    (options, args) = parser.parse_args()

    if len(args) != 1:
        parser.error("Incorrect number of arguments")

    if os.getuid() != 0:
        print "Please run as root"
        sys.exit(1)

    iface = args[0]
    dry_run = options.dry_run

    KRACKDetector(iface, dry_run).detect()

if __name__ == "__main__":
    main()
