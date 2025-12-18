# DNS Packet Capture (PCAP) Analysis Report  
### NIST SP 800-53 AC-6 (Least Privilege Compliance)

**Date:** 18th January, 2025  
**Entry:** 1  

---

## Description
This report documents a DNS packet analysis conducted to evaluate DNS queries, responses, and anomalies while ensuring compliance with **NIST SP 800-53 AC-6 (Least Privilege)**.

---

## Tools Used
- **Scapy (Python-based packet manipulation tool)**
- **Kali Linux (Debian-based) Virtual Machine**

Scapy was used to inspect DNS packet capture data, enabling packet parsing, filtering, and analysis. The analysis was conducted in a restricted environment to ensure minimal privilege access when handling sensitive network data.

---

## Analysis Procedure
The following steps were performed:

1. Loaded the PCAP file (`dns.cap`) using Scapy.  
2. Filtered DNS packets from the capture.  
3. Extracted and summarized DNS queries and responses.  
4. Identified potential anomalies such as unauthorized lookups or failed resolutions.  
5. Ensured analysis was conducted in a controlled and restricted environment.

---

## Findings and Observations

- **Total Packets Loaded:** 38  
- **Total DNS Packets Identified:** 38  

### Common Queries
- google.com  
- netbsd.org  
- example.com  
- isc.org  

### Notable Anomalies
- Multiple failed lookups for `GRIMM.utelsystems.local`  
- Query for `www.example.notginh` resulted in a name error  
- Reverse DNS lookup for `104.9.192.66.in-addr.arpa`  

---

## Reflections and Notes

### Challenges Faced
Filtering DNS packets efficiently using Scapy initially posed a challenge. Understanding Scapy syntax and structuring filtering logic required experimentation. This challenge was resolved through documentation review and iterative testing.

---

## Security Implications and Least Privilege Compliance

### Access Control Measures
- Restricted access enforced to protect sensitive DNS logs  

### Minimal Privilege Application
- Only authorized personnel had access to the packet capture file  
- Read-only permissions applied to prevent unauthorized modification  

### Detection of Unauthorized Queries
- Suspicious DNS lookups were identified, indicating potential misconfiguration or malicious activity  

---

## Recommendations
- Restrict unauthorized DNS queries through strict access controls  
- Continuously monitor and log DNS traffic for anomalies  
- Align internal security policies with **NIST SP 800-53 AC-6**  
- Deploy DNS filtering solutions to block malicious domains  

---

## Conclusion
This DNS packet analysis demonstrates compliance with **NIST SP 800-53 AC-6** by enforcing controlled access, identifying anomalies, and applying appropriate security measures. Continuous monitoring and refinement of access controls are recommended to maintain a strong network security posture.
