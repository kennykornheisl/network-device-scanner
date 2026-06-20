from scapy.all import ARP, Ether, srp
from manuf import MacParser

parser = MacParser()


def guess_device_type(vendor):
    v = (vendor or "").lower()

    if "apple" in v:
        return "📱 Phone/Laptop"
    if any(x in v for x in ["samsung", "xiaomi", "oneplus"]):
        return "📱 Phone"
    if any(x in v for x in ["intel", "dell", "hp", "lenovo", "microsoft"]):
        return "💻 Computer"
    if any(x in v for x in ["amazon", "google"]):
        return "🏠 Smart Device"
    return "❓ Unknown"


def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp

    answered = srp(packet, timeout=2, verbose=False)[0]

    devices = []

    for _, received in answered:
        mac = received.hwsrc
        vendor = parser.get_manuf(mac) or "Unknown"

        devices.append({
            "ip": received.psrc,
            "mac": mac,
            "vendor": vendor,
            "type": guess_device_type(vendor)
        })

    return devices