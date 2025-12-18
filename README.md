# CS-1
DNS Packet Analysis

---

## 📄 Analysis Report
A detailed technical report is available here in the repository


The report covers:
- Methodology
- Findings and anomalies
- Security implications
- Least privilege compliance
- Recommendations

---
## 🛠 Tools & Technologies
- Debian-based Kali Linux (Virtual Machine) 
- Python
- Scapy
- PCAP Analysis
- NIST SP 800-53 (AC-6)
  ### N:B- All files in data folder must be opened in the Debain-based Virtual Environment

## 📂 Data Handling
- **`dns.pcap`**: Original packet capture file  
- **`filtered_dns.pcap`**: DNS-only filtered packet capture  

### Why Filtering Matters
- Reduces exposure to unnecessary data
- Improves analysis efficiency
- Enforces least privilege by limiting access to sensitive traffic
- Reflects real-world SOC analyst workflow

> ⚠️ All PCAP files originate from a controlled lab environment and have been sanitized.

---

## 🧠 Analysis Workflow
1. Load raw PCAP file using Scapy  
2. Filter DNS packets from network traffic  
3. Save filtered DNS traffic to a separate PCAP  
4. Extract DNS queries and responses  
5. Identify anomalies such as failed resolutions and suspicious lookups  

---

## 🔐 Security & Ethics
- Analysis conducted in an **isolated virtual lab**
- **Read-only access** enforced on packet capture files
- No production or unauthorized networks were analyzed
- Aligned with ethical cybersecurity and compliance standards

---

## 📘 Compliance Alignment
This project demonstrates practical application of:

**NIST SP 800-53 – AC-6 (Least Privilege)** by:
- Restricting access to packet data
- Limiting exposure to only DNS-related traffic
- Preventing unauthorized modification of capture files
- Identifying potentially unauthorized DNS queries

---

## 📊 Key Skills Demonstrated
- DNS traffic analysis
- PCAP handling and filtering
- Python scripting with Scapy
- Network security fundamentals
- Least privilege enforcement
- Security documentation and reporting
- GRC-aware technical analysis

---

## 📜 License
This project is licensed under the **MIT License**.

---

## 👤 Author
**Sobanjo Oluwatosin M.**  
Cybersecurity Enthusiast | SOC & GRC-Focused Analyst  
