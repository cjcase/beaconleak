# beaconLeak on Windows

## Dependencies

* Python 3
* NPCap driver

## On Packet Injection

>*"It is important to realize that at this point in time, Windows can only be used for listening to network traffic. Windows cannot inject data packets. This is a fundamental limitation."* - Aircrack-ng Wiki

Both beaconLeak and Scapy assume packet injection capabilities by default. However, the capability to do so resides in both the driver and the firmware of the wireless NIC.   
During the development and research of this tool, no viable technique was found to make packet injection possible on Windows. While not impossible, further research must be done to enable packet injection in a reliable way.  
**Without packet injection capabilities, beaconLeak will only work in Detection mode (both offline and live) and partially in leak mode receiveing C2 commands. C2 mode will not be available.**

## Installation

Download the latest Python 3 binary installer for AMD64, run it with the option to "Add Python 3.x to PATH".  
Verify that it was correctly added to path by installing beaconleak dependencies with pip:

```
pip install -r requirements.txt
```

Download the latest Ncap binary installer.
In the NPCap installation, make sure to select "Support raw 802.11 traffic (and monitor mode) for wireless adapters", this will add support for monitor mode.

*Alternative: Download the latest Wireshark x64 binary. When installing wireshark, select the option "Install Npcap 0.99-r9".*

WlanHelper.exe will be installed along, the utilities will be saved in ```%WINDIR%\System32\Npcap```, so it is a good idea to add this to Window's PATH.

Before you can use WlanHelper to set monitor mode on, you will need to install the Visual C++ Redistributable for Visual Studio 2013.  
Run the following in an administrator command to verify its correctly installed:  

```
WlanHelper -i
```

## Usage

Use WlanHelper.exe to set the desired card in monitor mode, you can then run beaconLeak with the interface name as the example shows:

```
python beaconleak.py --mon "Intel(R) Centrino(R) Advanced-N 6205"
```