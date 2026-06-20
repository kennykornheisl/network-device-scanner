# network-device-scanner
A real-time network monitoring and analysis dashboard built with Python, Flask, and JavaScript.

Network Device Scanner continuously scans your local network, discovers connected devices, tracks activity over time, and provides live visualizations of netowrk health and behavior. The system maintains a historical memory of devices, estimates activity and bandwitdth usage, logs network evenbts, and can integrate with local AI models through Ollama for automated analysis.

# Features

## Device Discovery
- Automatically detects devices connected to your network
- Displays IP addresses, vendor information, and device details like activity, latency, estimated bandwidth
- Trakcs how many times each device has been seen
- Maintains persistent device memory between sessions
  - Stores known devices in a local JSON database
  - Tracks average activity over time

## Live Network Monitoring
- Real-time network activity graph
- Device latency measurements
- Activity scoring system
- Estimated bandwidth usage
- Connected devices counter
- Automatic refresh and updates

## Event Logging
- Device join and leave detection
- High latency warnings
- High activity anomaly detection
- Timestamped event history
- Live updating event feed

## AI-Powered Analysis
- Optional integration with Ollama
- Click to generate a report based on recent network activity and connected devices
- Highlights trends and anomalies/problematic devices, and summarizes unusual behavior



# Installation
Clone the repository:
``
git clone https://github.com/kennykornheisl/network-device-scanner.git
cd network-device-scanner
``

Install dependencies:
``
pip install flask scapy ping3 requests
``

Run the application:
``
python app.py
``

Open:
``
http://127.0.0.1:5000
``
