import threading
import time
import tkinter as tk
from scapy.all import *
import psutil
import socket
from scapy.all import IP, send, Ether, AsyncSniffer
from scapy.contrib.igmp import IGMP


class IGMPHost:
    def __init__(self, interface, log_callback, update_groups_callback):
        self.interface = interface
        self.group_memberships = set()
        self.running = True
        self.log_callback = log_callback
        self.update_groups_callback = update_groups_callback

        # Get MAC and IP addresses of the interface
        self.mac_address = self.get_mac_address(interface)
        self.ip_address = self.get_ip_address(interface)

    def get_mac_address(self, interface):
        addrs = psutil.net_if_addrs()[interface]
        for addr in addrs:
            if addr.family == psutil.AF_LINK:
                return addr.address.replace('-', ':')
        return None

    def get_ip_address(self, interface):
        addrs = psutil.net_if_addrs()[interface]
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.address
        return None

    def log(self, message):
        if self.log_callback:
            self.log_callback(message)

    def update_groups(self):
        if self.update_groups_callback:
            self.update_groups_callback(self.group_memberships)

    def join_group(self, group_address):
        if group_address not in self.group_memberships:
            report = Ether(src=self.mac_address) / IP(src=self.ip_address, dst=group_address) / IGMP(type=0x16, gaddr=group_address)
            sendp(report, iface=self.interface)
            self.group_memberships.add(group_address)
            self.log(f"Joined multicast group {group_address}")
            self.update_groups()

    def leave_group(self, group_address):
        if group_address in self.group_memberships:
            leave = Ether(src=self.mac_address) / IP(src=self.ip_address, dst="224.0.0.2") / IGMP(type=0x17, gaddr=group_address)
            sendp(leave, iface=self.interface)
            self.group_memberships.remove(group_address)
            self.log(f"Left multicast group {group_address}")
            self.update_groups()

    def listen_queries(self):
        def process_packet(packet):
            if packet.haslayer(IGMP):
                igmp = packet.getlayer(IGMP)
                if igmp.type == 0x11:  # IGMP Membership Query
                    self.process_query(igmp)

        self.sniffer = AsyncSniffer(iface=self.interface, prn=process_packet, filter="igmp")
        self.sniffer.start()

    def stop_listening(self):
        if hasattr(self, 'sniffer'):
            self.sniffer.stop()

    def process_query(self, igmp):
        if igmp.gaddr == "0.0.0.0":  # General Query
            self.log("Received General Query")
            self.respond_to_query()
        elif igmp.gaddr in self.group_memberships:  # Specific-Group Query
            self.log(f"Received Specific-Group Query for {igmp.gaddr}")
            self.respond_to_query(igmp.gaddr)

    def respond_to_query(self, group_address=None):
        if group_address:
            report = Ether(src=self.mac_address) / IP(src=self.ip_address, dst=group_address) / IGMP(type=0x16, gaddr=group_address)
            sendp(report, iface=self.interface)
            self.log(f"Sent Membership Report for group {group_address}")
        else:
            for group in self.group_memberships:
                report = Ether(src=self.mac_address) / IP(src=self.ip_address, dst=group) / IGMP(type=0x16, gaddr=group)
                sendp(report, iface=self.interface)
                self.log(f"Sent Membership Report for group {group}")

    def run(self):
        listener_thread = threading.Thread(target=self.listen_queries)
        listener_thread.start()

        listener_thread.join()

    def stop(self):
        self.running = False
        self.stop_listening()
        if threading.current_thread() != threading.main_thread():
            threading.current_thread().join()


class IGMPHostGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IGMP Host")

        self.interface_label = tk.Label(root, text="Network Interface:")
        self.interface_label.pack()

        self.interface_var = tk.StringVar(root)
        self.interface_menu = tk.OptionMenu(root, self.interface_var, *self.get_interfaces())
        self.interface_menu.pack()

        self.join_label = tk.Label(root, text="Join Multicast Group:")
        self.join_label.pack()

        self.group_entry = tk.Entry(root)
        self.group_entry.pack()

        self.join_button = tk.Button(root, text="Join Group", command=self.join_group)
        self.join_button.pack()

        self.leave_button = tk.Button(root, text="Leave Group", command=self.leave_group)
        self.leave_button.pack()

        self.groups_label = tk.Label(root, text="Joined Groups:")
        self.groups_label.pack()

        self.groups_listbox = tk.Listbox(root)
        self.groups_listbox.pack()

        self.log_text = tk.Text(root)
        self.log_text.pack()

        self.host = None

    def get_interfaces(self):
        interfaces = psutil.net_if_addrs().keys()
        return list(interfaces)

    def log_message(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def update_groups_display(self, group_memberships):
        self.groups_listbox.delete(0, tk.END)
        for group in group_memberships:
            self.groups_listbox.insert(tk.END, group)

    def start_host(self):
        interface = self.interface_var.get()
        self.host = IGMPHost(interface, self.log_message, self.update_groups_display)
        self.host_thread = threading.Thread(target=self.host.run)
        self.host_thread.start()

    def join_group(self):
        group = self.group_entry.get()
        if not group:
            self.log_message("Please enter a valid group address.")
            return

        if not self.host:
            self.start_host()

        self.host.join_group(group)

    def leave_group(self):
        selected_group = self.groups_listbox.get(tk.ACTIVE)
        if selected_group and self.host:
            self.host.leave_group(selected_group)

    def stop_host(self):
        if self.host:
            self.host.stop()
        if self.host_thread:
            self.host_thread.join()


if __name__ == "__main__":
    root = tk.Tk()
    app = IGMPHostGUI(root)
    root.mainloop()
