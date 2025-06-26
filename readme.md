# **Cyber Guard: SDN-Based Network Security with Honeypot Integration and Port Scanning Detection**

Cyber Guard is a Software-Defined Networking (SDN) project that enhances network security by integrating a POX-based OpenFlow controller with a Cowrie honeypot. It provides a real-time dashboard to monitor network events, including POX controller actions and honeypot activity. New features include real-time **port scan detection**.

## **Features**

* **POX-based SDN Controller:** Implements a security controller using POX, enforcing firewall rules, managing traffic flow, detecting SYN flood and port scan attacks.
* **Port Scan Detection:** Monitors rapid connections to multiple ports within a short time window, automatically blocking potential scanners.
* **Honeypot Integration:** Redirects SSH/Telnet traffic to a Cowrie honeypot, capturing and logging malicious interactions.
* **Real-time Dashboard:** A Flask-based web application provides a live view of controller logs and Cowrie honeypot events, including port scan attempts.
* **Network Address Translation (NAT):** Utilizes Mininet's NAT functionality to allow all hosts, including the honeypot, to access the internet for updates and external communication.
* **Dynamic Rule Enforcement:** The controller dynamically adds rules to block malicious traffic, SYN flood attackers, and port scanners.

## **Project Structure**

* `controller.py`: The POX OpenFlow security controller with firewall rules, SYN flood detection, port scan detection, and honeypot redirection.
* `dashboard.py`: Flask web application serving the security dashboard and API endpoints for controller and Cowrie logs.
* `index.html`: Frontend UI displaying real-time logs, attack charts, and statistics.
* `mini_topology.py`: Mininet topology including hosts, switch, controller, NAT, Cowrie, and dashboard services.

## **Prerequisites**

To run this project, you will need a Linux environment (preferably Ubuntu) with the following installed on your **host machine**:

* **Mininet:** A network emulator that creates virtual networks.

```bash
  git clone https://github.com/mininet/mininet  
  mininet/util/install.sh -a
```

* **POX:** An OpenFlow controller development platform.

```bash
  git clone https://github.com/noxrepo/pox
```

* **Cowrie:** A medium to high interaction SSH/Telnet honeypot.

```bash
  sudo apt update  
  sudo apt install python3-venv python3-dev python3-pip libssl-dev libffi-dev build-essential  
  git clone https://github.com/cowrie/cowrie.git  
  cd cowrie  
  python3 -m venv cowrie-env  
  source cowrie-env/bin/activate  
  pip install --upgrade pip  
  pip install -r requirements.txt  
  cp etc/cowrie.cfg.dist etc/cowrie.cfg  
  deactivate
```

**Note:** Cowrie needs to be run as a non-root user. The `mini_topology.py` script will attempt to run it as the cowrie user. Ensure this user exists and has necessary permissions for the Cowrie directory (`/home/cowrie/cowrie`).

```bash
  sudo adduser cowrie --shell /bin/bash --gecos "Cowrie Honeypot User" --disabled-password  
  sudo usermod -aG sudo cowrie # Optional, but can simplify initial setup  
  sudo chown -R cowrie:cowrie /home/cowrie/cowrie
```

* **Flask:** A Python web framework.

```bash
  pip install Flask Flask-Cors
```

## **Deployment Guide**

### **1. Clone the Repository**

```bash
git clone https://github.com/YazanAlJedawi/Cyber_guard.git
cd cyber_guard
```

### **2. Place Project Files**

* Copy `controller.py` into your POX directory:

```bash
  cp controller.py ~/pox/pox/
```

* Copy `dashboard.py` and `index.html` into a new directory on your host machine, e.g., `/app`:

```bash
  sudo mkdir -p /app  
  sudo cp dashboard.py /app/  
  sudo cp index.html /app/
```

> Adjust the `CONTROLLER_LOG_FILE` and `COWRIE_LOG_FILE` in `dashboard.py` and `mini_topology.py` to match your actual POX and Cowrie paths.
> Example:
>
> ```python
> CONTROLLER_LOG_FILE = os.path.expanduser('~/pox/pox/controller.log')
> COWRIE_LOG_FILE = os.path.expanduser('/home/cowrie/cowrie/var/log/cowrie/cowrie.json')
> ```

### **3. Start POX Controller**

```bash
cd ~/pox
./pox.py controller
```

### **4. Run Mininet Topology**

```bash
sudo python3 mini_topology.py
```

This will:

* Create the network topology (h1, h2, h100, server, cowrie, dashboard).
* Start Cowrie honeypot in its Mininet namespace.
* Launch http service on our dear server "10.0.0.10".
* Launch the dashboard server.
* Drop into the Mininet CLI.

### **5. Access the Dashboard**

Visit: [http://10.0.0.50:5000](http://10.0.0.50:5000)

### **6. Interact with the Network (from Mininet CLI)**

* **Ping (ICMP allowed):**

  ```bash
  h1 ping server
  ```
* **HTTPS server (allowed):**

  ```bash
  h1 curl http://10.0.0.10:443
  ```
* **Blocked traffic (h100 blocked):**

  ```bash
  h100 ping server
  ```

  Should show unreachable and be logged in POX.
* **Honeypot redirection (SSH/Telnet):**

  ```bash
  sudo ssh user@10.0.0.10
  sudo telnet 10.0.0.10
  ```

  These are redirected to Cowrie (10.0.0.200).
* **Simulate SYN Flood:**

  ```bash
  sudo hping3 --flood --syn -p 443 10.0.0.10
  ```

  After threshold, h100 is blocked.
* **Simulate Port Scan (NEW):**

  ```bash
   nmap -T4 -A 10.0.0.0/24
  ```


  This triggers port scan detection if ports are accessed rapidly within a time window.

### **7. Clean Up**

Exit the Mininet CLI with `exit`. Stop the POX controller manually (`Ctrl+C`).

## **Troubleshooting**

* **No logs appearing:**

  * Ensure POX and dashboard are running.
  * Double-check file paths for logs.
* **Cowrie not logging:**

  * Verify Cowrie user and permissions.
* **Port scanning not detected:**

  * Adjust thresholds in `controller.py` (`port_scan_threshold`, `port_scan_window`).
* **Dashboard error:**

  * Check JS console and `/tmp/dashboard.log`.

## **Contributing and License**

Feel free to contribute via pull requests or issues.

Y.