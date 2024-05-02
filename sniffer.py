from scapy.all import sniff, get_if_list, Packet, wrpcap

# Function to get network interface options
def get_interfaces():
  """Displays available network interfaces and returns the chosen one."""
  print("Available Interfaces:")
  for i, iface in enumerate(get_if_list()):
    print(f"{i+1}. {iface.name}")
  choice = int(input("Choose your interface (number): ")) - 1
  return get_if_list()[choice].name

# Function to capture and analyze packets
def capture_packets(iface, filename=None):
  """Sniffs packets on the chosen interface and optionally saves them to a file."""
  def analyze_packet(packet):
    # Print basic information
    print(f"Source: {packet[0].src}")
    print(f"Destination: {packet[0].dst}")
    print(f"Protocol: {packet.proto}")
    
    # Layer-specific analysis (example for TCP)
    if packet.haslayer(TCP):
      print(f"Source Port: {packet[TCP].sport}")
      print(f"Destination Port: {packet[TCP].dport}")

  # Capture packets with Scapy's sniff function
  packets = sniff(iface=iface, prn=analyze_packet)

  # Optionally write captured packets to a PCAP file
  if filename:
    wrpcap(filename, packets)
  
  print(f"Captured {len(packets)} packets!")

if __name__ == "__main__":
  # Get network interface choice
  iface = get_interfaces()

  # Capture options
  capture_option = input("Capture packets (y/n) or save to file (f): ")
  if capture_option.lower() == 'f':
    filename = input("Enter filename (pcap format): ")
    capture_packets(iface, filename)
  else:
    capture_packets(iface)
