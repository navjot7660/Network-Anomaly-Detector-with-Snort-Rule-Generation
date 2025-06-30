# 🕵️ Network Anomaly Detector with Snort Rule Generation

This project captures live network traffic using Scapy, extracts relevant features, and applies machine learning (Isolation Forest) to detect anomalous packets. It then generates Snort rules based on those anomalies to enhance intrusion detection.

## 🚀 Features

- Live packet capture (via Scapy)
- Feature extraction: IPs, ports, protocol, length, etc.
- ML-based anomaly detection using Isolation Forest
- Snort-compatible rule generation for flagged packets

## 📦 Requirements

Install dependencies in a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
▶️ Usage
Run the script with capture duration in seconds:

bash
Copy
Edit
sudo venv/bin/python anomaly_detector.py 60
Make sure your active network interface is correctly set (e.g., eth0, wlan0, etc.)

📄 Output
Snort rules are printed to the console

Optional: Saved to /etc/snort/rules/ai_generated_rules.rules

🧠 Note
For testing, generate traffic using tools like ping, curl, nmap, etc.

Works best in lab environments or VM setups with permission for raw socket access.
