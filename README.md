# Secure Multiprocess TCP Server

## 📌 Overview

This project implements a secure multiprocess TCP server application developed for the IE2102 Network Programming module. The system is built using the C programming language for the server and Python for the client, demonstrating core concepts of socket programming, process management, and network security.

The server is designed to handle multiple client connections concurrently using process forking while ensuring secure communication and authentication.

---

## ⚙️ Technologies Used

* C (Server Implementation)
* Python (Client Application)
* TCP Socket Programming
* Linux System Calls (`fork()`, `waitpid()`)
* Makefile (Build Automation)

---

## 🚀 Features

### 🔐 Authentication & Security

* Salted password hashing
* Session token generation and validation
* Login attempt lockout mechanism
* Rate limiting to prevent abuse
* Username validation
* Payload size restriction

### ⚡ Server Capabilities

* Concurrent client handling using `fork()`
* Custom TCP protocol with message framing
* Unique Server Identifier (SID:1039)
* Command-based client-server interaction

### 📊 Logging System

* Persistent audit logging
* Records:

  * Timestamp
  * Client IP & Port
  * Process ID (PID)
  * Username
  * Commands executed
  * Server responses

### 🧠 Process Management

* Proper child process handling using `waitpid()`
* No zombie processes
* Efficient resource management

---

## 🖥️ System Configuration

* Protocol: TCP
* Port: 50938
* Platform: Linux (Tested on Kali Linux)
* Compiler: `gcc`

---

## 🛠️ Build & Run Instructions

### 🔹 Compile the Server

```bash
make -f Makefile_3938
```

### 🔹 Run the Server

```bash
./server_3938
```

### 🔹 Run the Client

```bash
python3 client_3938.py
```

---

## 📡 Example Commands

* REGISTER username password
* LOGIN username password
* ECHO message
* WHOAMI

---

## 🔍 Testing & Validation

The system was tested for:

* Successful user registration and login
* Failed login attempts and lockout
* Concurrent client handling
* Logging accuracy
* Zombie process prevention

---

## 📁 Log File

```
server_IT24103938.log
```

Contains detailed records of all client interactions and system activities.

---

## 🎯 Learning Outcomes

* TCP socket programming
* Multiprocessing using `fork()`
* Secure authentication mechanisms
* System-level process management
* Logging and auditing techniques

---

## 📌 Conclusion

This project demonstrates a complete and secure client-server architecture capable of handling multiple clients concurrently while ensuring system security, stability, and traceability. It highlights practical implementation of networking and operating system concepts in a real-world scenario.

---

## 👨‍💻 Author

Arosha Sampath
SLIIT - Network Programming Module
