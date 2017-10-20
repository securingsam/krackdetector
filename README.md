![KRACK](https://www.commitstrip.com/wp-content/uploads/2017/10/Strip-Faille-WP2-650-finalenglish.jpg)
## KRACK Detector

KRACK Detector is a Python script to detect possible [KRACK attacks](https://www.krackattacks.com) against client devices on your network.
The script is meant to be run on the Access Point rather than the client devices. It listens on the Wi-Fi interface and waits for duplicate message 3 of the 4-way handshake. It then disconnects the suspected device, preventing it from sending any further sensitive data to the Access Point.

KRACK Detector currently supports Linux Access Points with [hostapd](https://w1.fi/hostapd).
It uses Python 2 for compatibility with older operating systems. No external Python packages are required.

## Usage

Run as root and pass the Wi-Fi interface as a single argument. It is important to use the actual Wi-Fi interface and not any bridge interface it connects to.

```
python krack_detect.py wlan0
```

If you do not wish to disconnect suspected devices, use the `-n` flag

```
python krack_detect.py -n wlan0
```

## Known Issues
Message 3 of the 4-way handshake might be retransmitted even if no attack is perfomed. In such a case the client device will be disconnected from the Wi-Fi network. Some client devices will take some time to re-authenticate themselves, losing the Wi-Fi connection for a few seconds.
