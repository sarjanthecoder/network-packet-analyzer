Real-Time Packet Capture: Sniffs network traffic live using Scapy.

Live Web Dashboard: Uses Flask-SocketIO (WebSockets) to push data to the frontend without refreshing.

Protocol Distribution: A doughnut chart visualizes the breakdown of TCP, UDP, ICMP, and other protocols.

Top Source IPs: A bar chart shows the most active IP addresses on your network.

Recent Packets Table: A filterable, auto-updating table displays details for the most recent packets.

Web-Based Controls: Start, stop, and clear the capture session directly from the browser.

🛠️ Technology Stack
Backend:

Python 3

Flask (Web server)

Flask-SocketIO (Real-time WebSocket communication)

Scapy (Packet sniffing and analysis)

Frontend:

HTML5

CSS3

JavaScript

Socket.IO (Client)

Chart.js (Data visualization)

📋 Requirements & Installation
1. Prerequisite: Npcap (Windows)
This tool performs low-level packet sniffing, which requires a special driver.

Windows: You MUST install Npcap.

Crucial Step: During the Npcap installation, you MUST check the box for "Install Npcap in WinPcap API-compatible Mode". Scapy needs this to function.

Linux/macOS: You will need libpcap installed, which usually comes pre-installed. If not, use your package manager (e.g., sudo apt install libpcap-dev).

2. Project Setup
Download or Clone: Download and unzip the project files to a folder.

File Structure: Flask requires the index.html file to be in a folder named templates. Your folder should look like this:

/network
    ├── app.py
    ├── templates/
    │   └── index.html
(If your index.html is in the same folder as app.py, create a new folder named templates and move index.html into it.)
Install Python Dependencies: Create a file named requirements.txt in your project folder, paste the following into it, and save it.

requirements.txt

Flask
Flask-SocketIO
scapy
Here is a comprehensive README.md file for your project. This file is essential for anyone (including your future self!) who wants to understand, install, and run your application.

Just copy the text below and save it as README.md in your project folder (C:\Users\sarja\Downloads\network).

NetAnalyzer: Real-Time Network Traffic Analyzer
NetAnalyzer is a web-based tool built with Python, Flask, and Scapy to capture and analyze your local network traffic in real-time. It provides a live, interactive dashboard to monitor packet flow, protocol distribution, and top IP addresses.

![]

🚀 Features
Real-Time Packet Capture: Sniffs network traffic live using Scapy.

Live Web Dashboard: Uses Flask-SocketIO (WebSockets) to push data to the frontend without refreshing.

Protocol Distribution: A doughnut chart visualizes the breakdown of TCP, UDP, ICMP, and other protocols.

Top Source IPs: A bar chart shows the most active IP addresses on your network.

Recent Packets Table: A filterable, auto-updating table displays details for the most recent packets.

Web-Based Controls: Start, stop, and clear the capture session directly from the browser.

🛠️ Technology Stack
Backend:

Python 3

Flask (Web server)

Flask-SocketIO (Real-time WebSocket communication)

Scapy (Packet sniffing and analysis)

Frontend:

HTML5

CSS3

JavaScript

Socket.IO (Client)

Chart.js (Data visualization)

📋 Requirements & Installation
1. Prerequisite: Npcap (Windows)
This tool performs low-level packet sniffing, which requires a special driver.

Windows: You MUST install Npcap.

Crucial Step: During the Npcap installation, you MUST check the box for "Install Npcap in WinPcap API-compatible Mode". Scapy needs this to function.

Linux/macOS: You will need libpcap installed, which usually comes pre-installed. If not, use your package manager (e.g., sudo apt install libpcap-dev).

2. Project Setup
Download or Clone: Download and unzip the project files to a folder.

File Structure: Flask requires the index.html file to be in a folder named templates. Your folder should look like this:

/network
    ├── app.py
    ├── templates/
    │   └── index.html
(If your index.html is in the same folder as app.py, create a new folder named templates and move index.html into it.)

Create a Virtual Environment (Recommended):

Bash

# Create the environment
python -m venv venv

# Activate it (Windows)
.\venv\Scripts\activate

# Activate it (Linux/macOS)
source venv/bin/activate
Install Python Dependencies: Create a file named requirements.txt in your project folder, paste the following into it, and save it.

requirements.txt

Flask
Flask-SocketIO
scapy
Now, run the installer:

Bash

pip install -r requirements.txt
⚡ How to Run
This is the most important step. Because packet sniffing accesses the network adapter directly, you must run the script as an administrator.

On Windows
Click the Start Menu.

Type PowerShell or cmd.

Right-click on it and select "Run as administrator".

In the administrator terminal, navigate to your project folder:
python app.py
Access the Dashboard
Once the server is running (you'll see Starting Flask-SocketIO server on http://0.0.0.0:5000), open your web browser and go to:

http://127.0.0.1:5000

Click "🚀 Start Analyzing" and then "▶ Start Capture" to begin monitoring.
