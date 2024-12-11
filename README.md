# PythonSec

## Prerequisites

python

scapy


## Install Honeypot OpenCanary

```bash
sudo apt-get install python3-dev python3-pip python3-virtualenv python3-venv python3-scapy libssl-dev libpcap-dev
virtualenv env/
. env/bin/activate
pip install opencanary paramiko requests mysql-connector-python
```

## Install scapy

⚠️ Install scapy with **root** provileges

```bash
sudo pip install scapy
```

## Execute OpenCanary

Configuration

```bash
opencanaryd --copyconfig
```

Running OpenCanary

```bash
. env/bin/activate
opencanaryd --start
```

Stopping OpenCanary

```bash
opencanaryd --stop
```

## Test NIDS

```bash
sudo python3 nids.py
python3 attacks_simulator.py
```
