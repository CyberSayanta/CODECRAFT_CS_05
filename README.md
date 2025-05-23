🌐 Network Packet Analyzer
⚠️ Ethical Use Notice
This project is intended solely for educational and ethical use.
Unauthorized network monitoring or packet sniffing may violate privacy laws and organizational policies. Use this tool only on networks you own or have explicit permission to analyze.

📘 Project Overview
Task 05 - Code Craft Challenge

The Network Packet Analyzer is a basic packet sniffer tool designed to capture and analyze network traffic. It helps users understand the structure and flow of network packets by displaying key attributes such as source and destination IPs, protocols, and payloads.

🔍 Features
📡 Captures live packets on your local network

🌐 Displays:

Source IP address

Destination IP address

Protocol used (TCP, UDP, ICMP, etc.)

Packet payload (in a readable format)

🧪 Great for cybersecurity learning and traffic analysis

🛠️ Technologies Used
💻 Programming Language: Python (recommended with scapy/socket)

📦 Libraries:

scapy for packet capturing and dissection

socket for basic networking operations

🖥️ Compatible with Windows/Linux

⚙️ Installation & Usage
1. Clone the Repository
   https://github.com/CyberSayanta/CODECRAFT_CS_05.git
2. Install Dependencies
   pip install scapy
3. Run the Sniffer
   sudo python packet_sniffer.py

⚠️ Root/Administrator access may be required to capture network traffic.

📄 Sample Output
Source: 192.168.1.10 → Destination: 93.184.216.34 | Protocol: TCP | Payload: GET / HTTP/1.1...

📌 Important Considerations
📶 Use this tool on a private network for learning and monitoring.

👥 Never analyze traffic on networks without explicit consent.

🛡️ This tool does not decrypt HTTPS or interfere with encrypted content.


🚀 Future Improvements
📊 Real-time dashboard with graphical visualization

📁 Save packet logs to .pcap files

📂 Protocol filtering and search tools

📉 Bandwidth statistics tracking

📄 License
This project is licensed under the MIT License. See LICENSE for more details.
