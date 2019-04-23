# beaconLeak

beaconLeak is an open source tool developed as a proof
of concept of the beacon stuffing method as a covert channel,
allowing data exfiltration using the wireless network card. This tool includes
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
*partially supported, please check in the repository.*

1. Set up a virtual environment

```
# python -m venv bl
```

2. Load Python virtual environment

```
# source bl/bin/activate
```

3. Install the Python Library Requirements

```
pip install -r requirements.txt
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
                            by cjcase [v0.8.90]

    

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

## License

```
beaconLeak - Covert data exfiltration and detection using beacon stuffing
Copyright (C) 2019 Cj Case

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

## Acknowledgements

This tool was inspired by the "bridging the airgap" work of Mordecai Guri. 
A previous description of the beacon stuffing method for exfiltration was 
described by Tom Neaves.
Basic implementation of this method predates beaconLeak, existing tool
 [PyExfil](https://github.com/ytisf/PyExfil/) by Yuval Nativ. 
This project was developed as a research project for Tallinn University of 
Technology's Cyber Security Master programme and funded by the Dora Plus fund.

![Dora Plus](http://haridus.archimedes.ee/sites/default/files/styles/medium/public/eu_regional_development_fund_horizontal_0.jpg)