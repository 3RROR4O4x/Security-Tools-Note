# Security-Tools-Note
Notes and Breakdown of security tools(Nmap, Wireshark,etc)
Tool writeup and expample for Nmap,Wireshark,Metasploit basics and more
Day 1 Lab — Networking Foundations (practical)
Overview

# In today’s lab you’ll:

- Identify the active network interface and MAC address on your Kali machine.

- Capture live network traffic and inspect ARP and ICMP packets.

- Capture and analyze a TCP 3-way handshake.

- Do a safe local host discovery (scan).

- Use Netcat to create a basic socket connection.

- Produce a short timeline of key packets and run a simple parsing script to extract MAC pairs.

- Each activity includes: what to do, why, what you should see, and troubleshooting tips.

Preparation (quick checks)

Ensure you have sudo privileges and the following tools installed: tcpdump, tshark/wireshark, nmap, netcat, python3 and scapy.

If using a VM, make sure networking is set to a mode you understand (bridged if you want to see other LAN hosts; NAT if you only want internet access from the VM).

Create a working folder to save captures and notes.

🔹Lab Step 1 — Find the active interface (what to do)

List interfaces and addresses to find which interface has an IPv4 address.

Check the routing table to see which interface is used for the default route (i.e., internet traffic).

Why: You need to know which interface to monitor; otherwise you may capture nothing useful.

What you should see: An interface name like eth0, ens33, enp0s3, or wlan0 with an IP such as 192.168.x.x. The routing table will show a line with default via <gateway> dev <iface> indicating the active interface.

Troubleshoot: If you see no IP, your VM may be disconnected or set to host-only. Change VM adapter mode or reconnect.

🔹Lab Step 2 — Identify your MAC address (what to do)

Inspect the chosen interface to find its hardware (MAC) address.

Why: MAC addresses are used on the local link; they appear in every Ethernet frame and are required to interpret captures.

What you should see: A 6-byte address like 08:00:27:12:34:56 labelled link/ether for the interface.

Troubleshoot: Some virtual adapters use locally-assigned MACs. That’s normal — just note the MAC shown.

🔹Lab Step 3 — Capture ARP & ICMP traffic (what to do)

Start a packet capture on the active interface.

While capturing, ping a public IP (e.g., 8.8.8.8) and ping your gateway.

Stop the capture and open it in a packet viewer.

Why: ARP shows how IPs map to MACs on the LAN. ICMP (ping) shows basic reachability. Capturing both lets you see the chain: ARP (who-has) → ARP reply → ICMP echo request/reply.

What you should see:

ARP requests shown as broadcast frames asking “Who has X.X.X.X?”

ARP replies mapping IP → MAC.

ICMP echo requests and replies between your host and the target.

🔹Troubleshoot:

If you don’t see ARP, your interface may already have ARP cached entries — check the ARP table to confirm.

If no packets at all, verify you captured on the correct interface and that your VM mode allows that traffic.

Lab Step 4 — Inspect a TCP 3-way handshake (what to do)

Start a capture focused on TCP.

From the same host, make a simple HTTP request (or any TCP connection).

Stop and analyze the capture, looking specifically for SYN → SYN/ACK → ACK.

Why: Understanding the handshake explains how TCP establishes reliable connections before data transfer.

What you should see: Three packets in sequence: a SYN from your host, a SYN/ACK from the server, then an ACK from your host. After the ACK, the application data (HTTP headers) will follow.

Troubleshoot:

If you see SYN but not SYN/ACK, the remote server might be unreachable, or a firewall is blocking responses.

If nothing appears, check DNS resolution — the host may not have resolved the domain you requested.

Lab Step 5 — Basic local network scan (what to do)

Determine your local subnet and run a host discovery scan to find live devices.

Why: Scanning shows you the devices visible on your LAN. It’s the basic reconnaissance step attackers and defenders both perform.

What you should see: A list of IPs reported as “host up”, optionally with MAC addresses and vendor info for local ARP-based detection.

Safety note: Only scan networks you own or have authorization for.

Troubleshoot:

If the scan returns few hosts, ensure your subnet is correct. Some networks isolate clients so scans won’t reveal all devices.

Lab Step 6 — Netcat: basic socket test (what to do)

Open a TCP listener on a port. Connect to it from another terminal (same host or different host) and exchange messages.

Why: Netcat demonstrates raw socket communication and lets you observe payloads and connection behavior without application-layer abstractions.

What you should see: Typed messages appearing on both ends; corresponding TCP frames in your capture with payloads.

Troubleshoot: If connection fails, check that the listener is running on the expected interface/port and that local firewall rules aren’t blocking it.

Lab Step 7 — Make a short PCAP timeline and parse MAC pairs (what to do)

Use a packet viewer to create a simple timeline: find where DHCP/ARP/DNS/TCP events occur and note packet numbers/times.

Run a small script that reads the PCAP and outputs unique source→destination MAC pairs.

Why: A timeline helps you explain what happened during the capture, and parsing scripts show how to automate repetitive analysis tasks.

What you should see: A concise timeline listing things like “Packet 12 — ARP who-has; Packet 13 — ARP reply; Packet 47–49 — TCP handshake; Packet 50 — HTTP GET.”

Troubleshoot: If your script fails to parse the PCAP, ensure the file was captured correctly and the script expects the right file format.

Reflection / Teaching Prompts

After completing the lab, ask yourself (or your students) to explain:

Why ARP is necessary on a LAN, and how ARP spoofing can be abused.

How MAC and IP addresses differ in role and scope.

What a SYN flood attack would attempt to do to the TCP handshake.

How defenders can monitor ARP or long-lived outbound connections to detect suspicious behavior.

Common pitfalls & quick fixes

No traffic captured → Wrong interface, capture permissions, or VM network mode. Re-check interface selection and permissions.

Wireshark shows nothing → Try capturing with tcpdump and then open the saved file; ensure you have permission (dumpcap config) or run as a user allowed to capture.

Scanning yields no hosts → Ensure scanning network is the same subnet and that host discovery method (ARP vs ICMP) is appropriate for the environment.

Script errors → Confirm dependencies (Scapy installed) and that the PCAP path is correct.

What to save as proof / deliverables

Capture files for ARP/ICMP and for the TCP handshake.

A short timeline note (a paragraph or bullet list) describing the main events and packet numbers.

The parsing script and its output.

Short notes on anything unusual you observed. 
