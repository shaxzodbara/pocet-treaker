import os
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import *
from scapy.layers.http import HTTPRequest  # For HTTP packet decoding
from scapy.layers.dns import DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS

# Global variables
capturing = False
selected_ip = None
captured_data = []

# Decode and identify protocol details
def analyze_packet(packet):
    global captured_data

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        if selected_ip and (src != selected_ip and dst != selected_ip):
            return  # Filter by selected IP

        summary = f"[{src} -> {dst}] Protocol: {proto}\n"

        # HTTP
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            host = http_layer.Host.decode() if http_layer.Host else ""
            path = http_layer.Path.decode() if http_layer.Path else ""
            method = http_layer.Method.decode() if http_layer.Method else ""
            summary += f"  HTTP {method} http://{host}{path}\n"

        # DNS
        elif packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode()
            summary += f"  DNS Query for {query}\n"

        elif packet.haslayer(DNSRR):
            response = packet[DNSRR].rdata
            summary += f"  DNS Response: {response}\n"

        # TLS SNI (HTTPS domain detection)
        elif packet.haslayer(TLSClientHello):
            sni = packet[TLSClientHello].ext.get("server_name", b"").decode(errors='ignore')
            if sni:
                summary += f"  TLS SNI (HTTPS Domain): {sni}\n"

        # Raw Payload
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                decoded = payload.decode('utf-8', errors='ignore')
                summary += f"  Payload: {decoded[:200]}\n"
            except:
                summary += f"  Payload: <non-text binary data>\n"

        summary += "-" * 50 + "\n"
        captured_data.append(summary)
        update_gui(summary)

# GUI update function
def update_gui(summary):
    output_text.configure(state='normal')
    output_text.insert(tk.END, summary)
    output_text.configure(state='disabled')
    output_text.yview(tk.END)

# Sniffing thread
def start_sniffing(interface):
    sniff(iface=interface, prn=analyze_packet, store=False)

# Button callback
def toggle_capture():
    global capturing
    if not capturing:
        interface = interface_entry.get()
        threading.Thread(target=start_sniffing, args=(interface,), daemon=True).start()
        capture_button.config(text="Stop Capture")
        capturing = True
    else:
        capturing = False
        capture_button.config(text="Start Capture")

# IP Filter callback
def set_ip_filter():
    global selected_ip
    selected_ip = ip_entry.get().strip()

# Save PCAP
def save_pcap():
    wrpcap("captured_traffic.pcap", captured_data)

# GUI Setup
root = tk.Tk()
root.title("Advanced Packet Sniffer")

frame = ttk.Frame(root, padding=10)
frame.pack(fill=tk.BOTH, expand=True)

interface_label = ttk.Label(frame, text="Interface:")
interface_label.grid(row=0, column=0, sticky=tk.W)
interface_entry = ttk.Entry(frame)
interface_entry.insert(0, "wlan0")
interface_entry.grid(row=0, column=1, sticky=tk.W)

ip_label = ttk.Label(frame, text="Filter IP:")
ip_label.grid(row=0, column=2, sticky=tk.W)
ip_entry = ttk.Entry(frame)
ip_entry.grid(row=0, column=3, sticky=tk.W)

set_ip_btn = ttk.Button(frame, text="Set IP Filter", command=set_ip_filter)
set_ip_btn.grid(row=0, column=4, padx=5)

capture_button = ttk.Button(frame, text="Start Capture", command=toggle_capture)
capture_button.grid(row=1, column=0, pady=5)

save_button = ttk.Button(frame, text="Save PCAP", command=save_pcap)
save_button.grid(row=1, column=1, pady=5)

output_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=120, height=30, state='disabled')
output_text.grid(row=2, column=0, columnspan=5, pady=10)

root.mainloop()
