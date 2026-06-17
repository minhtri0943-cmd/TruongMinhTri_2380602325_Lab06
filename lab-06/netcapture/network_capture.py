from scapy.all import *
from scapy.arch.windows import get_windows_if_list

def get_interfaces():
    """Lấy danh sách giao diện mạng từ Scapy (tương thích Windows)"""
    ifaces = get_windows_if_list()
    return ifaces

def packet_handler(packet):
    if packet.haslayer(Raw):
        print("Captured Packet:")
        print(str(packet))

# Lấy danh sách các giao diện mạng
interfaces = get_interfaces()

# In danh sách giao diện mạng để người dùng lựa chọn
print("Danh sách các giao diện mạng:")
for i, iface in enumerate(interfaces, start=1):
    name = iface.get("name", "Unknown")
    description = iface.get("description", "")
    print(f"{i}. {name} - {description}")

# Lựa chọn giao diện mạng từ người dùng
choice = int(input("Chọn một giao diện mạng (nhập số): "))
selected_iface = interfaces[choice - 1]["name"]

print(f"\nĐang bắt gói tin trên: {selected_iface}")
print("Nhấn Ctrl+C để dừng...\n")

# Bắt gói tin trên giao diện mạng được chọn
sniff(iface=selected_iface, prn=packet_handler, filter="tcp")
