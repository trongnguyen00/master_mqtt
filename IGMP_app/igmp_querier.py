import threading
import time
import tkinter as tk
from scapy.all import *
import psutil
import socket
from scapy.all import IP, send, Ether, AsyncSniffer
from scapy.contrib.igmp import IGMP


class IGMPQuerier:
    def __init__(self, interface, log_callback, update_members_callback):
        self.interface = interface
        self.group_members = {}
        self.running = True
        self.robustness_variable = 2
        self.query_interval = 10
        self.max_response_time = 100
        self.log_callback = log_callback
        self.update_members_callback = update_members_callback

        # Lấy địa chỉ MAC và IP của interface
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

    def update_members(self):
        if self.update_members_callback:
            self.update_members_callback(self.group_members)

    def listen_reports(self):
        def process_packet(packet):
            if packet.haslayer(IGMP):
                igmp = packet.getlayer(IGMP)
                if igmp.type == 0x16:  # IGMPv2 Membership Report
                    group_address = igmp.gaddr
                    src_address = packet[IP].src
                    self.process_report(group_address, src_address)
                elif igmp.type == 0x17:  # IGMPv2 Leave Group
                    group_address = igmp.gaddr
                    src_address = packet[IP].src
                    self.process_leave(group_address, src_address)

        self.sniffer = AsyncSniffer(iface=self.interface, prn=process_packet, filter="igmp")
        self.sniffer.start()

    def stop_listening(self):
        if hasattr(self, 'sniffer'):
            self.sniffer.stop()

    def process_report(self, group_address, src_address):
        if group_address in self.group_members:
            self.group_members[group_address].add(src_address)
        else:
            self.group_members[group_address] = {src_address}
        self.log(f"Received IGMP report from {src_address} for group {group_address}")
        self.update_members()

    def process_leave(self, group_address, src_address):
        if group_address in self.group_members and src_address in self.group_members[group_address]:
            self.group_members[group_address].remove(src_address)
            if not self.group_members[group_address]:
                del self.group_members[group_address]
            self.send_group_specific_query(group_address)  # Send query for the group
        self.log(f"Received IGMP leave from {src_address} for group {group_address}")
        self.update_members()

    def send_general_query(self):
        query = Ether(src=self.mac_address) / IP(src=self.ip_address, dst="224.0.0.1") / IGMP(type=0x11, gaddr="0.0.0.0")
        for _ in range(self.robustness_variable):
            if not self.running:
                break
            sendp(query, iface=self.interface)
            self.log("Sent general IGMP query")
            self.sleep_with_check(self.query_interval)

    def send_group_specific_query(self, group_address):
        query = Ether(src=self.mac_address) / IP(src=self.ip_address, dst=group_address) / IGMP(type=0x11, gaddr=group_address)
        for _ in range(self.robustness_variable):
            if not self.running:
                break
            sendp(query, iface=self.interface)
            self.log(f"Sent group-specific IGMP query to group {group_address}")
            self.sleep_with_check(self.query_interval)

    def sleep_with_check(self, duration):
        step = 0.1
        for _ in range(int(duration / step)):
            if not self.running:
                break
            time.sleep(step)

    def query_groups(self):
        while self.running:
            self.send_general_query()
            self.sleep_with_check(self.query_interval)

    def run(self):
        listener_thread = threading.Thread(target=self.listen_reports)
        listener_thread.start()

        query_thread = threading.Thread(target=self.query_groups)
        query_thread.start()

        listener_thread.join()
        query_thread.join()

    def stop(self):
        self.running = False
        self.stop_listening()
        if threading.current_thread() != threading.main_thread():
            threading.current_thread().join()



class IGMPQuerierGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IGMP Querier")

        self.interface_label = tk.Label(root, text="Network Interface:")
        self.interface_label.pack()

        self.interface_var = tk.StringVar(root)
        self.interface_menu = tk.OptionMenu(root, self.interface_var, *self.get_interfaces())
        self.interface_menu.pack()

        self.start_button = tk.Button(root, text="Start Querier", command=self.start_querier)
        self.start_button.pack()

        self.stop_button = tk.Button(root, text="Stop Querier", command=self.stop_querier, state=tk.DISABLED)
        self.stop_button.pack()

        self.log_text = tk.Text(root)
        self.log_text.pack()

        self.members_text = tk.Text(root, height=10)
        self.members_text.pack()

        self.querier = None
        self.querier_thread = None

    def get_interfaces(self):
        interfaces = psutil.net_if_addrs().keys()
        return list(interfaces)

    def log_message(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def update_members_display(self, group_members):
        self.members_text.delete(1.0, tk.END)
        for group, members in group_members.items():
            self.members_text.insert(tk.END, f"Group: {group}\n")
            for member in members:
                self.members_text.insert(tk.END, f"  - {member}\n")
            self.members_text.insert(tk.END, "\n")
        self.members_text.see(tk.END)

    def start_querier(self):
        interface = self.interface_var.get()
        if not interface:
            self.log_message("Please select a network interface")
            return
        try:
            self.querier = IGMPQuerier(interface, self.log_message, self.update_members_display)
            self.querier_thread = threading.Thread(target=self.querier.run)
            self.querier_thread.start()

            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.log_message("IGMP Querier started")
        except ValueError as e:
            self.log_message(f"Error: {e}")

    def stop_querier(self):
        if self.querier:
            self.querier.stop()
        if self.querier_thread:
            self.querier_thread.join()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log_message("IGMP Querier stopped")


if __name__ == "__main__":
    root = tk.Tk()
    app = IGMPQuerierGUI(root)
    root.mainloop()
