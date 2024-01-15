from scapy.all import ARP, Ether, srp

def discover_devices(ip_range):
    # Create ARP-request to get MAC-adresses of devices in the network
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether/arp

    # Send ARP-request and get responses
    result = srp(packet, timeout=3, verbose=0)[0]

    # Processing and output info
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

# Output function
if __name__ == "__main__":
    ip_range = input("Write range of IP-Adresses (for example, 192.168.1.1/24 !MASK Necessarily! ): ")

    devices = discover_devices(ip_range)

    if devices:
        print("\nSuch devices have been found:")
        for device in devices:
            print(f"IP-Adress: {device['ip']}, MAC-Adress: {device['mac']}")
        print('You can check every MAC-Adress on Oui Lookup and get names of devices')
    else:
        print("Devices have not been found.")
