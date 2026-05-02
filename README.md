# 🔐 Secure Concurrent TCP Server

## 📌 Overview
This project is a secure TCP server developed using C and socket programming. It supports multiple clients and implements several security mechanisms.

## 🚀 Features
- User Registration & Login
- Password Hashing
- Token-based Authentication
- Protected Commands (PING, TIME, UPTIME)
- Brute Force Protection (3 login attempts)
- Rate Limiting
- Custom Message Framing Protocol
- Concurrent Clients using fork()
- Logging System

## 🛠️ Technologies Used
- C (POSIX Sockets)
- Python (Client Testing)
- TCP/IP Networking
- Linux (Ubuntu/Kali)

## ▶️ How to Run

### Compile Server
I have created a makefile

### Run Server
./server_2980

### Run Client
python3 client_2980.py

## 🔒Security Concepts Implemented

Authentication & Authorization
Brute-force Attack Prevention
DoS Protection (Rate Limiting)
Secure Session Handling (Tokens)

## 📂Project Structure

server_2980.c → Main server logic
client_2980.py → Client implementation
log file → Server logs

## 👨‍💻 Author
Nimnaka Vitharana (IT Undergraduate - Cyber Security)


