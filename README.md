# DNS Traffic Analyzer

The **DNS Traffic Analyzer** is a Python-based tool designed to capture, analyze, and report DNS traffic. It provides insights into DNS queries, flags, and entropy, helping identify potential anomalies such as DNS tunneling, misconfigurations, or malicious activities.

---

## Features

- **Packet Capture**: Captures DNS packets over UDP port 53 for a user-defined duration.
- **Entropy Calculation**: Computes Shannon entropy for domain names to detect suspicious patterns.
- **DNS Flag Parsing**: Decodes DNS flags into human-readable formats.
- **Detailed Reporting**:
    - **JSON Output**: Saves analysis results in a structured JSON file.
    - **PDF Report**: Generates a professional PDF report with detailed insights.
- **Remarks Generation**: Provides remarks based on entropy and DNS flags to highlight potential issues.

---

## Installation

1. Clone the repository:
     ```bash
     git clone https://github.com/your-repo/dns-analyzer.git
     cd dns-analyzer
     ```

2. Install dependencies:
     ```bash
     pip install -r requirements.txt
     ```

---

## Usage

1. Run the script:
     ```bash
     python Dns_Analyser.py
     ```

2. Enter the duration (in seconds) for DNS packet capture when prompted.

3. After capturing, the tool will:
     - Save captured packets to `dns_capture.pcap`.
     - Analyze the packets and save results to:
         - `output.json` (JSON format)
         - `dns_report.pdf` (PDF report)

---

## Output Files

- **dns_capture.pcap**: Raw captured DNS packets.
- **output.json**: JSON file containing detailed analysis results.
- **dns_report.pdf**: PDF report summarizing the analysis.

---

## Example PDF Report

![PDF Report Example](https://via.placeholder.com/800x400?text=PDF+Report+Preview)

---

## Remarks and Insights

- **High Entropy Domains**: Indicates potential DNS tunneling or DGA (Domain Generation Algorithm) activity.
- **Refused Queries**: Highlights DNS queries refused by the server.
- **Unsuccessful Responses**: Identifies misconfigurations or potential attacks.

---

## Dependencies

- **Python 3.6+**
- **Scapy**: For packet capture and analysis.
- **NumPy**: For entropy calculation.
- **ReportLab**: For generating PDF reports.

Install dependencies using:
```bash
pip install scapy numpy reportlab
```

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Developed By

**Group 5**  
Contributors:  
- [Contributor 1](https://github.com/contributor1)  
- [Contributor 2](https://github.com/contributor2)  
- [Contributor 3](https://github.com/contributor3)

---

## Disclaimer

This tool is intended for educational and research purposes only. Ensure you have proper authorization before capturing network traffic.
