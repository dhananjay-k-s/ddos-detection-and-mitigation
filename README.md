# DDoS Attack Detection and Mitigation System

This project implements an intelligent DDoS (Distributed Denial of Service) attack detection and mitigation system using Software-Defined Networking (SDN) and Machine Learning techniques. The system is built using the Ryu SDN controller and utilizes various ML algorithms to detect and mitigate DDoS attacks in real-time.

## Project Structure

The project is organized into several key components:

### Controller Module (`controller/`)
- `KNN_controller.py`, `KNN_con.py`, `KNN_con1.py`: Different implementations of K-Nearest Neighbors based traffic classification
- `KNN_mit.py`: KNN-based mitigation controller
- `DT_controller.py`: Decision Tree based traffic classification
- `RF_controller.py`: Random Forest based traffic classification
- `switch.py`: Base switch implementation for SDN control

### Machine Learning Module (`ml/`)
- `ML.py`: Main machine learning implementation with multiple algorithms
- `LR.py`: Logistic Regression classifier
- `KNN.py`: K-Nearest Neighbors classifier
- `SVM.py`: Support Vector Machine classifier
- `NB.py`: Naive Bayes classifier
- `DT.py`: Decision Tree classifier
- `RF.py`: Random Forest classifier

### Mininet Module (`mininet/`)
- `topology.py`: Network topology definition
- `generate_benign_trafic.py`: Generation of normal network traffic
- `generate_ddos_trafic.py`, `generate_ddos_trafic1.py`: Generation of DDoS attack traffic

### Root Directory
- `mitigation_module.py`: Core DDoS attack mitigation implementation

## Features

- Real-time traffic monitoring and analysis
- Multiple ML algorithms for traffic classification:
  - K-Nearest Neighbors (KNN)
  - Logistic Regression (LR)
  - Support Vector Machine (SVM)
  - Naive Bayes (NB)
  - Decision Tree (DT)
  - Random Forest (RF)
- Automated DDoS attack detection
- Immediate mitigation response
- Traffic flow statistics collection
- Dynamic flow rule installation

## Requirements

- Python 3.x
- Ryu SDN Framework
- Mininet
- scikit-learn
- pandas
- numpy
- matplotlib

## Installation

1. Install the required dependencies:
```bash
pip install ryu pandas numpy scikit-learn matplotlib
```

2. Install Mininet (if not already installed):
```bash
sudo apt-get install mininet
```

## Usage

1. Start the Ryu controller with the desired ML algorithm:
```bash
ryu-manager controller/KNN_controller.py
```

2. In a separate terminal, start the Mininet topology:
```bash
sudo python mininet/topology.py
```

3. Generate normal traffic:
```bash
h1 ./traffic_scripts/normal_traffic.sh &
```

4. To simulate a DDoS attack:
```bash
h7 ./traffic_scripts/ddos_attack.sh &
```

## Project Implementation Details

### Network Topology
- Implements a custom network topology with multiple switches and hosts
- Uses OpenFlow 1.3 protocol
- Supports various traffic types (TCP, UDP, ICMP)

### Traffic Classification
- Collects flow statistics (packet count, byte count, duration, etc.)
- Processes and normalizes traffic features
- Uses trained ML models to classify traffic as normal or DDoS

### DDoS Mitigation
- Automatically blocks detected attack sources
- Installs flow rules to filter malicious traffic
- Monitors traffic patterns continuously
- Adapts to changing attack patterns

### Machine Learning Pipeline
1. Data Collection: Gather flow statistics from network traffic
2. Feature Extraction: Process raw data into meaningful features
3. Model Training: Train selected ML algorithm
4. Real-time Classification: Classify incoming traffic
5. Mitigation: Take action based on classification results

## File Descriptions

### Controller Files
- `KNN_controller.py`: Main KNN-based traffic classifier and controller
- `KNN_mit.py`: Implements mitigation strategies using KNN
- `switch.py`: Basic OpenFlow switch functionality

### ML Files
- `ML.py`: Implements the core ML functionality and model training
- Individual algorithm files (LR.py, KNN.py, etc.): Specific implementations of each ML algorithm

### Mininet Files
- `topology.py`: Defines the network structure and host configurations
- `generate_benign_trafic.py`: Scripts for generating normal network traffic
- `generate_ddos_trafic.py`: Scripts for simulating DDoS attacks

## Performance Metrics

The system evaluates performance using:
- Accuracy scores for each ML algorithm
- Confusion matrices for classification results
- Real-time traffic analysis statistics
- Detection and mitigation response times

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

This project is available for use under the MIT License.
