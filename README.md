# beaconLeak

beaconLeak is an open source tool developed as a proof
of concept of the beacon stuffing method for covert data exfiltration
using the wireless network card. This tool includes the necessary functionality
to both leak data as an attacker and detect the beacon stuffing method for 
defense purposes. Detection mode creates basic indicators of compromise to be 
consumed by monitoring or correlation security systems.

## Description

The beacon stuffing attack is a wireless physical attack so wireless proximity
is required. Because  of the need to push custom frames through the wireless 
interface, the tool must be run with either root privileges or network admin 
capabilities.  
This tool uses Scapy to transmit the 802.11 (Dot11) frames, and pyNaCL to have
all data encrypted on transit.

* c2 mode: remote cover shell
* leak mode: file exfiltration
* detect mode: detect the use of this method

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

This tool was inspired by the work of Mordecai Guri. A previous description
of the beacon stuffing method for exfiltration was described by Tom Neaves.  
This project was developed as a research project for Tallinn University of 
Technology's Cyber Security Master programme and funded by the Dora Plus fund.

![Dora Plus](http://haridus.archimedes.ee/sites/default/files/EU_Regional_Development_Fund_horizontal.jpg)