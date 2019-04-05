# beaconLeak on android (root needed)

## Pre-requisites

You will need a **rooted android device**.  
If your android device WiFi doesn't support monitor mode, you can use an USB OTG cable to connect an external WiFi card that supports it.

## Dependencies

* termux
  * tsu
  * git
  * clang
  * python-dev
  * libsodium-dev
  * libffi-dev
  * cmake
  * python
    * scapy==2.4.0


## Installation

Run as normal user:

```bash
pkg update
pkg install tsu git clang python python-dev libsodium-dev libffi-dev cmake
tsu
```

Allow root access and then run the following:

```bash
mkdir bl
cd bl
python -m venv blenv
source blenv/bin/activate
pip install scapy==2.4.0
git clone https://github.com/pyca/pynacl
cd pynacl
# git checkout cf132ab (if current build does not work)
find . -type f -not -path '*/\.*' -exec sed -i 's%/bin/sh%/data/data/com.termux/files/usr/bin/sh%g' {} \;
python setup.py install
exit
```

*if python setup fails, remove the pynacl git repo, clone again and use the git checkout to pull the tested commit.*

Back as normal user, install iw and optionally aircrack (for using airmon-ng)

```bash
pkg install root-repo
pkg install iw ethtool aircrack-ng
```

get root, load the virtual env again, set up monitor mode and run:

```bash
tsu
source blenv/bin/activate
iw dev wlan0 set type monitor # OR airmon-ng start wlan0
python beaconleak.py --c2 wlan0mon
```

## Setting monitor mode

beaconleak needs a wifi card in monitor mode to operate correctly, if your device has one, you need to first set it in monitor mode for it to work

## Experimental

*There might be a chance that you can run beaconleak on any non-rooted device if you have an external wifi card with the RTL8187 chipset, this however is untested. Check the following link for more info: https://www.kismetwireless.net/static/android-pcap/*

For the adventurous:
https://null-byte.wonderhowto.com/how-to/android-cyanogenmod-kernel-building-monitor-mode-any-android-device-with-wireless-adapter-0162943/

## Resources

https://wiki.termux.com/wiki/Instructions_for_installing_python_packages