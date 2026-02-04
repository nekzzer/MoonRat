
# 🌑 MoonRat

**A basic Remote Administration Tool (RAT) concept that uses blockchain technology as a decentralized command-and-control (C2) server. Simple, lightweight, and experimental.**

---

## 🏗 Project Structure

Based on the current architecture:

* `app.py` — Flask-based web interface for managing the botnet.
* `blockchain.py` — Core logic for blockchain interaction.
* `client.go` — The actual RAT client (payload) written in Go.
* `/templates` & `/static` — UI components for the C2 panel.
* `config.json`, `keys.json`, `blockchain_users.json` — Configuration, cryptographic keys, and user data.

## 🚀 Installation & Usage

### 1. Requirements

* **Python 3.x** (for the C2 Panel)
* **Go 1.20+** (to compile the client)

### 2. Setup the C2 Panel (Backend)

```bash
# Install python dependencies
pip install flask

# Start the control panel
python app.py

```

After starting, access the dashboard via `index.html` (templates are in `/templates`).

### 3. Build the Client (Go)

```bash
# Initialize go modules
go mod tidy

# Compile the payload
go build client.go

```

## ⚠️ Liability & Responsibility

The authors (**nekzzer** and **kriska1337**) are **not responsible** for how this tool is used. We take no responsibility for the actions of **orixman** or any other individuals who decide to use, modify, or distribute this RAT.

If you have trouble understanding the code or need technical help, **go ask ChatGPT**. We are not your tech support.

## ⚖️ Legal Disclaimer

Educational purposes only. Using this tool on targets without prior mutual consent is illegal.

---

### Credits

Created by **nekzzer** and **kriska1337**

> **orixman соси мой хуй я эту хуйню все равно солью**

---
