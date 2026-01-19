# Web Server Compromise - Network Forensics Analysis
**Category:** Network Forensics

**Platform:** CyberDefenders

**Tool Used:** Wireshark

## Lab Description
Analyze captured network traffic using Wireshark to investigate a web server compromise. The objective is to identify malicious activity including web shell upload, reverse shell communication, and data exfiltration.

## Scenario Summary
A suspicious file was discovered on a company web server, raising concerns of unauthorized access within the internal network. The Development team escalated the issue to security, suspecting a potential breach.

To support the investigation, the Network team captured network traffic related to the incident and provided a PCAP file for forensic analysis.

## Objective:
Analyze the PCAP file to determine:
- Identify the source of the attack
- Determine how the web server was compromised
- Identify attacker tools and techniques
- Assess potential data exfiltration

## Tactics Observed:
- Initial Access
- Execution
- Persistence
- Command and Control (C2)
- Exfiltration

## Intial Traffic Analysis & Attack Origin
The PCAP file was opened in Wireshark to establish an overview of the captured traffic.

![PCAP](screenshots/open_pcap.png)

Early analysis revealed consistent communication between two IP addresses:
- 24.49.63.79 – Identified as the web server
- 117.11.88.124 – Suspected external attacker

To validate this observation, IPv4 endpoint statistics were reviewed:
![ipv4](screenshots/ipv4_endpoints.png)

## Investigation & Findings

## Key Takeaways
