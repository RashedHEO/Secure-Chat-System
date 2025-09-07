# Secure Chat System

A secure end-to-end encrypted chat application built in **Java**, designed with a client-server architecture.  
This project demonstrates strong foundations in **network security, encryption, and GUI development**, making it suitable for real-world secure communication scenarios.

---

## Features
- **Secure Communication**: All messages are encrypted using SSL/TLS with RSA keys.  
- **Client-Server Model**: Multiple clients can connect and exchange encrypted messages through the server.  
- **Graphical User Interface (GUI)**: Both server and client applications include a clean and unified chat interface.  
- **Secure Log Monitoring**: The server includes a monitoring window to track encrypted communication events.  
- **Cross-Network Support**: Clients can connect to the server over the same network (LAN/Wi-Fi).  

---

## Project Structure
/src
├── Server.java # Secure chat server with GUI
├── Client.java # Secure chat client with GUI
├── Monitor.java # Secure log monitoring system
├── utils/ # Utility classes for SSL and security configuration
└── keystores/ # Contains server and client keystore files


---

## Requirements
- **Java JDK 20+**  
- **Eclipse IDE** or command-line (javac/java)  
- **Git** for version control  

---

## Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/RashedHEO/Secure-Chat-System.git
   cd Secure-Chat-System


Generate SSL keystores (server & client):

keytool -genkeypair -alias serverkey -keyalg RSA -keystore serverkeystore.jks -keysize 2048 -storepass password -keypass password
keytool -genkeypair -alias clientkey -keyalg RSA -keystore clientkeystore.jks -keysize 2048 -storepass password -keypass password


Run the server:

java Server


Run the client:

java Client

Why This Project Matters for Companies

Security-Oriented Design: Uses SSL/TLS encryption to ensure confidentiality and integrity of data.

Scalability: Built with modular classes, easily extendable to enterprise-level secure messaging systems.

Real-World Application: Can be adapted for internal corporate messaging, secure logging, or encrypted data transfer.

Demonstrates Skills In:

Java networking and concurrency

Secure key management (RSA/SSL)

GUI development (Swing)

Software architecture and modular design

License
This project is released under the MIT License.
