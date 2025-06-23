# **Cyber Guard: SDN-Based Network Security with Honeypot Integration**

Cyber Guard is a Software-Defined Networking (SDN) project that enhances network security by integrating a POX-based OpenFlow controller with a Cowrie honeypot. It provides a real-time dashboard to monitor network events, including POX controller actions and honeypot activity.

## **Features**

* **POX-based SDN Controller:** Implements a security controller using POX, enforcing firewall rules, managing traffic flow, and detecting SYN flood attacks.  
* **Honeypot Integration:** Redirects SSH/Telnet traffic to a Cowrie honeypot, capturing and logging malicious interactions.  
* **Real-time Dashboard:** A Flask-based web application provides a live view of controller logs and Cowrie honeypot events.  
* **Network Address Translation (NAT):** Utilizes Mininet's NAT functionality to allow all hosts, including the honeypot, to access the internet for updates and external communication.  
* **Dynamic Rule Enforcement:** The controller dynamically adds rules to block malicious traffic and SYN flood attackers.

## **Project Structure**

* controller.py: The POX OpenFlow security controller. This script defines firewall rules, handles packet-in events, redirects traffic to the honeypot, and implements SYN flood detection.  
* dashboard.py: A Flask web application that serves the network security dashboard and provides API endpoints for fetching logs from the POX controller and Cowrie honeypot.  
* index.html: The frontend HTML, CSS, and JavaScript for the real-time network security dashboard. It visualizes logs from both the POX controller and the Cowrie honeypot.  
* mini_topology.py: A Mininet script that defines the network topology, including hosts, switches, a remote controller, a NAT node, and starts the POX controller, Cowrie honeypot, and the Flask dashboard.

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

  **Note:** Cowrie needs to be run as a non-root user. The mini_topology.py script will attempt to run it as the cowrie user. Ensure this user exists and has necessary permissions for the Cowrie directory (/home/cowrie/cowrie). You might need to create the user and adjust permissions:  
```bash
  sudo adduser cowrie --shell /bin/bash --gecos "Cowrie Honeypot User" --disabled-password  
  sudo usermod -aG sudo cowrie \# Optional, but can simplify initial setup  
  sudo chown -R cowrie:cowrie /home/cowrie/cowrie
```

* **Flask:** A Python web framework.  
```bash
  pip install Flask Flask-Cors
```

## **Deployment Guide**

Follow these steps to set up and run the Cyber Guard project:

### **1\. Clone the Repository**

First, clone this GitHub repository to your Linux machine:

```bash
git clone https://github.com/YazanAlJedawi/Cyber_guard.git  
cd cyber_guard
```

### **2\. Place Project Files**

Ensure your project files are placed in the correct directories for Mininet and POX to find them:

* Copy controller.py into your POX directory:  
```bash
  cp controller.py \~/pox/pox/
```

* Copy dashboard.py and index.html into a new directory on your host machine, for example, /app:  
```bash
  sudo mkdir -p /app  
  sudo cp dashboard.py /app/  
  sudo cp index.html /app/
```

  You might need to adjust the COWRIE_LOG_FILE and CONTROLLER_LOG_FILE paths in dashboard.py and mini_topology.py if your POX and Cowrie installations are in different locations than specified in the code.  
  * CONTROLLER_LOG_FILE \= os.path.expanduser('/home/zandar/pox/pox/controller.log')  
  * COWRIE_LOG_FILE \= os.path.expanduser('/home/cowrie/cowrie/var/log/cowrie/cowrie.json')

Important: Update /home/zandar/pox/pox/controller.log to reflect your actual POX installation path on your host machine. For example, if POX is in \~/pox, it would be \~/pox/pox/controller.log.Similarly, ensure COWRIE_LOG_FILE points to your Cowrie log directory on your host machine. The dashboard.py script (running on the dashboard Mininet host) will attempt to read these logs from these paths on your host.

### **3\. Start POX Controller**

Open a new terminal on your **host machine** and navigate to your POX directory. Start the POX controller with your controller.py script:

```bash
cd \~/pox  
./pox.py misc.controller --port=6633 \# The port 6633 is specified in mini_topology.py
```

Leave this terminal running.

### **4\. Run Mininet Topology**

Open another new terminal on your **host machine**. Navigate to the directory where you cloned the Cyber Guard repository. Run the Mininet topology script:

```bash
sudo python3 mini_topology.py
```

This script will:

* Create the network topology (h1, h2, h100, server, cowrie, dashboard).  
* Start the Cowrie honeypot on the cowrie Mininet host (which will access the Cowrie installation from your host machine).  
* Start the Flask dashboard server on the dashboard Mininet host (which will access dashboard.py from the /app directory on your host).  
* Drop you into the Mininet CLI.

### **5\. Access the Dashboard**

Once the Mininet CLI is active, the dashboard server should be running. Open your web browser on your **host machine** and navigate to:

http://10.0.0.50:5000

You should see the "Network Security Dashboard" displaying live logs.

### **6\. Interact with the Network (from Mininet CLI)**

From the Mininet CLI, you can interact with the network to generate logs and observe the security features:

* **Ping (ICMP allowed):**  
  h1 ping server

* **Access HTTPS server (allowed):**  
  h1 curl http://10.0.0.10:443

* **Test blocked traffic (h100 blocked):**  
  h100 ping server

  You should see "Destination Host Unreachable" and a "Firewall: DENY by default" message in the POX controller log on the dashboard.  
* **Test honeypot redirection (SSH/Telnet to server):**  
  h1 ssh 10.0.0.10  
  h1 telnet 10.0.0.10

  These attempts will be redirected to the Cowrie honeypot (10.0.0.200) and you'll see connection and command logs appearing in the "Cowrie Honeypot Activity" section of the dashboard. Try entering some commands in the emulated SSH/Telnet session.  
* **Simulate SYN Flood (from h100 to server):**  
  h100 hping3 --flood --syn -p 443 10.0.0.10

  After a threshold, the controller will detect the SYN flood from h100 and permanently block its traffic, which will be reflected in the POX logs.

### **7\. Clean Up**

When you are done, exit the Mininet CLI by typing exit. This will stop the Mininet network.  
Remember to stop the POX controller manually by pressing Ctrl+C in its terminal.

## **Troubleshooting**

* **"Controller log file not found." / "Error: Could not connect to the backend server."**:  
  * Ensure the POX controller is running in a separate terminal on your host machine.  
  * Verify the CONTROLLER_LOG_FILE and COWRIE_LOG_FILE paths in dashboard.py and mini_topology.py are correct for your system.  
  * Check if the Flask dashboard server started successfully in the Mininet script output (look for "Dashboard is running").  
* **Cowrie not starting or logging**:  
  * Ensure the cowrie user exists on your host machine and has appropriate permissions for the Cowrie installation directory (/home/cowrie/cowrie).  
  * Check Cowrie's own logs (e.g., in /home/cowrie/cowrie/var/log/cowrie/cowrie.log or cowrie.json) for errors.  
  * Make sure you ran source cowrie-env/bin/activate and pip install -r requirements.txt within the Cowrie directory on your host machine.  
* **Mininet errors**:  
  * Ensure Mininet is installed correctly.  
  * Run sudo mn --clean to clean up any previous Mininet instances.  
* **No logs appearing on the dashboard**:  
  * Check your browser's developer console for JavaScript errors.  
  * Verify that dashboard.py is running and accessible from the Mininet host (dashboard.cmd('python3 dashboard.py')).

Feel free to contribute to this project by opening issues or submitting pull requests\!

**Disclaimer:** This project is for educational and experimental purposes. Do not deploy it in a production environment without significant modifications and security hardening.