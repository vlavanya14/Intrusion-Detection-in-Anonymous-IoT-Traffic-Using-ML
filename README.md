# Intrusion Detection in Anonymous IoT Traffic Using ML

![Status](https://img.shields.io/badge/status-active-success)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

An intelligent Intrusion Detection System (IDS) for IoT networks that uses Machine Learning to detect anomalous patterns and security threats in real-time network traffic.

## 🎯 Overview

This project implements a comprehensive intrusion detection solution designed specifically for IoT environments. It combines machine learning classification with real-time network monitoring capabilities to identify malicious activities and anomalous patterns in IoT traffic.

### Key Features

- **Real-Time Monitoring**: Live intrusion detection using MQTT streaming
- **Machine Learning Classification**: Random Forest-based anomaly detection
- **Interactive Dashboard**: Streamlit-based web interface for visualization
- **CSV Data Processing**: Batch analysis of network traffic logs
- **Dual Input Modes**: Support for both live monitoring and historical data analysis
- **Feature Extraction**: Automated extraction of IoT network features
- **Sensor Simulation**: Built-in tools for testing and demonstration

## 📋 Project Structure

```
.
├── app.py                   # Main Streamlit dashboard application
├── feature_extractor.py     # MQTT listener and feature extraction from IoT data
├── predictor.py             # Model prediction and inference module
├── sensor_simulator.py       # IoT sensor simulation for testing
├── wokwi_extractor.py       # Network traffic extraction from Wokwi simulations
├── requirements.txt         # Python dependencies
├── rf_model.joblib          # Pre-trained Random Forest model
├── rl_config.joblib         # Configuration for the detection system
└── README.md                # This file
```

## 🔧 Technology Stack

- **Machine Learning**: scikit-learn (Random Forest)
- **Data Processing**: pandas, numpy
- **Streaming**: paho-mqtt (MQTT client)
- **Web Dashboard**: Streamlit
- **Model Serialization**: joblib
- **MQTT Broker**: HiveMQ Cloud

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/vlavanya14/Intrusion-Detection-in-Anonymous-IoT-Traffic-Using-ML.git
cd Intrusion-Detection-in-Anonymous-IoT-Traffic-Using-ML
```

2. **Create and activate a virtual environment**
```bash
# Windows
python -m venv venv
.\venv\Scripts\Activate.ps1

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

## 🚀 Usage

### Option 1: Launch the Dashboard

Start the interactive Streamlit dashboard:

```bash
streamlit run app.py
```
Website Link [App](https://vlavanya14-intrusion-detection-in-anonymous-iot-traf-app-nesp4y.streamlit.app/)

**Upload CSV File Mode**
- Upload network traffic logs in CSV format
- View predictions and anomaly scores
- Identify intrusions in historical data

**Live MQTT Monitoring Mode**
- Real-time stream from connected IoT devices
- Live visualization of network traffic
- Instant threat detection and alerting

### Option 2: Use Feature Extractor

Connect to IoT devices via MQTT and extract features:

```bash
python feature_extractor.py
```

This will:
- Connect to HiveMQ Cloud broker
- Listen for incoming sensor data
- Extract network features
- Save predictions to `live_data.csv`

### Option 3: Run Sensor Simulator

Test the system with simulated IoT sensors:

```bash
python sensor_simulator.py
```

### Option 4: Extract Wokwi Simulation Data

Process network data from Wokwi simulations:

```bash
python wokwi_extractor.py
```

## 🤖 Model Details

### Random Forest Classifier
- **Algorithm**: Random Forest
- **Trained on**: Network traffic features
- **Output**: Binary classification (Normal / Intrusion)
- **Threshold**: 0.6 (configurable)
- **Features Used**: Model configuration stored in `rf_model.joblib`

### Anomaly Detection
- Probability-based scoring system
- Anomaly scores > threshold indicate potential intrusions
- Configurable detection thresholds via `rl_config.joblib`

## 📊 Sample Workflow

1. **Prepare Data**
   - Network traffic in CSV format or MQTT stream

2. **Feature Extraction**
   - Automatic extraction of relevant IoT network features

3. **Prediction**
   - Random Forest model classifies traffic as normal or intrusive

4. **Visualization**
   - Dashboard displays results with anomaly scores and attack counts

5. **Action**
   - Identify and respond to detected threats

## ⚙️ Configuration

### MQTT Connection (feature_extractor.py)
```python
BROKER = "3698a45a8d964ea5a18398d6fee3ad2d.s1.eu.hivemq.cloud"
PORT = 8883
TOPIC = "agriot/sensor/data"
```

### Detection Threshold (app.py)
```python
THRESHOLD = 0.6  # Adjust based on your sensitivity requirements
```

## 📈 Performance Metrics

The system provides:
- Total packets analyzed
- Attack detection count
- Anomaly scores per packet
- Real-time threat indicators

## 🔐 Security Considerations

- Uses encrypted MQTT connections (port 8883)
- Credentials should be stored in environment variables (not in code)
- Pre-trained model includes built-in protection thresholds
- Features automatically normalized and preprocessed

## 🛠️ Troubleshooting

**No live data appearing?**
- Ensure MQTT credentials are correct
- Check network connectivity to HiveMQ Cloud
- Verify IoT devices are publishing to the correct topic

**Model not loading?**
- Confirm `rf_model.joblib` exists in project root
- Check file permissions

**Dashboard not responding?**
- Restart Streamlit: `streamlit run app.py`
- Clear cache: Delete `.streamlit` folder

## 📝 Data Format

Expected CSV columns for batch analysis:
- Network traffic features (source IP, destination IP, protocol, port, etc.)
- Packet size, duration, and other statistical features
- Timestamp information (optional)

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs and issues
- Suggest improvements
- Submit pull requests
- Enhance documentation

## 📄 License

This project is licensed under the MIT License - see LICENSE file for details.

## 👤 Author

**Lavanya** - [@vlavanya14](https://github.com/vlavanya14)

## 🙏 Acknowledgments

- scikit-learn team for the Random Forest implementation
- Streamlit for the interactive web framework
- HiveMQ for the MQTT brokering service
- IoT and ML research communities

---

**Note**: This is a proof-of-concept system for educational and research purposes. For production deployment, additional security hardening and extensive testing is recommended.
