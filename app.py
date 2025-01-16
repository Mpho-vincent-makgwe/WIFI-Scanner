from flask import Flask, render_template, request, jsonify
import os
import subprocess
from scapy.all import ARP, Ether, srp
from pywifi import PyWiFi, const, Profile
import socket
import threading
import logging


app = Flask(__name__)

def scan_wifi():
    """Scans for available Wi-Fi networks using PyWiFi."""
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]  # Select the first Wi-Fi interface
    iface.scan()  # Initiate the scan
    
    import time
    time.sleep(3)  # Allow time for the scan to complete
    
    results = iface.scan_results()  # Get the scan results
    networks = []
    for result in results:
        networks.append({
            "ssid": result.ssid,
            "signal": result.signal,
            "bssid": result.bssid,
            "auth": result.auth,
        })
    return networks



def connect_to_wifi(ssid):
    """Connects to an open Wi-Fi network using PyWiFi."""
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]  # Select the first Wi-Fi interface

    profile = Profile()  # Create a new profile
    profile.ssid = ssid  # Set the SSID of the network
    profile.auth = const.AUTH_ALG_OPEN  # Set authentication to open (no password)

    iface.remove_all_network_profiles()  # Remove all existing profiles
    temp_profile = iface.add_network_profile(profile)  # Add the new profile

    iface.connect(temp_profile)  # Attempt to connect
    import time
    time.sleep(5)  # Wait for the connection to establish

    if iface.status() == const.IFACE_CONNECTED:
        return "Connected successfully"
    else:
        return "Failed to connect"

def get_network_info():
    """Fetches MAC address, IP address, and scans for open ports."""
    network_info = {"mac_address": None, "ip_address": None, "ports": []}
    try:
        # Get the default gateway and IP address
        ip_address = socket.gethostbyname(socket.gethostname())
        network_info["ip_address"] = ip_address

        # Get the MAC address
        arp_request = ARP(pdst="192.168.1.1/24")
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        for _, response in answered_list:
            network_info["mac_address"] = response.hwsrc
            break

        # Scan for open ports
        for port in range(1, 1025):  # Scan only well-known ports
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                network_info["ports"].append(port)
            sock.close()

    except Exception as e:
        network_info["error"] = str(e)

    return network_info


@app.route('/')
def home():
    return render_template("index.html")

@app.route('/scan', methods=['GET'])
def scan():
    networks = scan_wifi()
    return jsonify(networks)


@app.route('/connect', methods=['POST'])
def connect():
    ssid = request.json.get("ssid")
    result = connect_to_wifi(ssid)
    return jsonify({"message": result})

@app.route('/network_info', methods=['GET'])
def network_info():
    info = get_network_info()
    return jsonify(info)

if __name__ == '__main__':
    app.run(debug=True)
    
logging.basicConfig(level=logging.DEBUG)