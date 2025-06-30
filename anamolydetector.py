import scapy.all as scapy
import pandas as pd
import numpy as np
import sys
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime

class NetworkAnomalyDetector:
    def __init__(self, interface='eth0', duration=60):
        self.interface = interface
        self.duration = duration
        self.packets_df = None

    def capture_packets(self):
        print(f"Capturing packets on {self.interface} for {self.duration} seconds")
        captured_packets = scapy.sniff(iface=self.interface, timeout=self.duration)
        self._parse_packets(captured_packets)

    def _parse_packets(self, packets):
        packet_features = []
        for packet in packets:
            if packet.haslayer('IP'):
                feature_vector = {
                    'timestamp': datetime.now(),
                    'protocol': packet['IP'].proto,
                    'src_ip': packet['IP'].src,
                    'dst_ip': packet['IP'].dst,
                    'src_port': packet.sport if hasattr(packet, 'sport') else 0,
                    'dst_port': packet.dport if hasattr(packet, 'dport') else 0,
                    'packet_length': len(packet)
                }
                packet_features.append(feature_vector)
        
        self.packets_df = pd.DataFrame(packet_features)

    def detect_anomalies(self):
        if self.packets_df is None or self.packets_df.empty:
            print("No packets captured")
            return []

        # Prepare features for anomaly detection
        features = self.packets_df[['protocol', 'src_port', 'dst_port', 'packet_length']]
        
        # Scale features
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)

        # Detect anomalies
        clf = IsolationForest(contamination=0.1, random_state=42)
        y_pred = clf.fit_predict(scaled_features)
        
        # Filter anomalous packets
        anomalous_packets = self.packets_df[y_pred == -1]
        return anomalous_packets

    def generate_snort_rules(self, anomalous_packets):
        rules = []
        for _, packet in anomalous_packets.iterrows():
            rule = f"""alert ip {packet['src_ip']} any -> {packet['dst_ip']} {packet['dst_port']} (
    msg:"Anomalous Traffic Detected";
    sid:{np.random.randint(100000, 99999999)};
    rev:1;
)"""
            rules.append(rule)
        return rules

def main():
    # Initialize detector
    try:
        time_capture = int(sys.argv[1])
    except (ValueError, IndexError):
        print("Usage: python script.py <capture_duration_in_seconds>")
        sys.exit(1)

    detector = NetworkAnomalyDetector(interface='eth0', duration=time_capture)
    
    # Capture packets
    detector.capture_packets()
    
    # Detect anomalies
    anomalous_packets = detector.detect_anomalies()
    
    # Generate Snort rules
    rules = detector.generate_snort_rules(anomalous_packets)
    
    # Print or save rules
    print("Generated Snort Rules:")
    for rule in rules:
        print(rule)
    
    # Optional: Save rules to file
    with open('/etc/snort/rules/ai_generated_rules.rules', 'w') as f:
        f.write('\n'.join(rules))

if __name__ == "__main__":
    main()
