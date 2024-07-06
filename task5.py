from scapy.all import sniff, IP, TCP, UDP
import datetime

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Determine protocol
        if protocol == 6:  # TCP
            protocol_name = 'TCP'
        elif protocol == 17:  # UDP
            protocol_name = 'UDP'
        else:
            protocol_name = 'Other'

        # Create a log entry with timestamp
        log_entry = f"{datetime.datetime.now()} - {src_ip} -> {dst_ip} [{protocol_name}]"

        # Add payload data if available
        if TCP in packet or UDP in packet:
            payload = packet[TCP].payload if TCP in packet else packet[UDP].payload
            log_entry += f" - Payload: {str(payload)}"
        
        print(log_entry)

        # Save log to a file
        with open("packet_log.txt", "a") as log_file:
            log_file.write(log_entry + "\n")

def main():
    # Sniff packets on the network interface
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
