# PythonSec



## Install Honeypot OpenCanary

```bash
sudo apt-get install python3-dev python3-pip python3-virtualenv python3-venv python3-scapy libssl-dev libpcap-dev
virtualenv env/
. env/bin/activate
pip install opencanary paramiko requests mysql-connector-python
```

Configuration

```bash
opencanaryd --copyconfig
```

Running OpenCanary

```bash
. env/bin/activate
opencanaryd --start
```

Install libraries

```bash
pip install paramiko requests mysql-connector-python
```

Stopping OpenCanary

```bash
opencanaryd --stop
```
