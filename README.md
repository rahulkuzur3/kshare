# ⚡ KShare Pro: Legendary P2P Transfer
> **Fast. Secure. Direct.** Transfer files between PC and Mobile with zero internet required.

![GitHub License](https://img.shields.io/github/license/rahulkuzur/kshare?style=for-the-badge)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Android-green?style=for-the-badge)

**KShare** is a high-performance, Peer-to-Peer (P2P) file sharing application built with Python and Kivy. It bypasses the cloud entirely, connecting devices directly via local sockets for maximum speed and privacy.

---

## ✨ Features

- 🚀 **Lightning Fast:** Uses direct TCP sockets for maximum transfer speeds on your local network.
- 📸 **QR Connection:** Simply scan the receiver's QR code on mobile to connect instantly.
- 🖥️ **Cross-Platform:** Seamlessly share files between **Windows PCs** and **Android devices**.
- 📊 **Live Progress:** Beautiful UI with real-time percentage tracking for both sender and receiver.
- ⚙️ **Persistent Settings:** Custom download paths that the app remembers.
- 🛡️ **Privacy First:** No servers, no data logging, no internet required. Just P2P.

---

## 📸 Screenshots

| Main Menu | Sender UI | Receiver UI (QR) |
| :---: | :---: | :---: |
| ![Menu](https://via.placeholder.com/200x400?text=Menu+UI) | ![Sender](https://via.placeholder.com/200x400?text=Sender+UI) | ![Receiver](https://via.placeholder.com/200x400?text=Receiver+QR) |

---

## 🛠️ Tech Stack

- **Language:** Python 3.12
- **Framework:** Kivy (NUI)
- **Networking:** Python Sockets (TCP/IP)
- **Image Processing:** OpenCV & Pyzbar (QR Scanning)
- **Packaging:** PyInstaller (Windows EXE) & Buildozer (Android APK)

---

## 🚀 Quick Start

### 1. Prerequisites
Ensure you have Python installed, then install the dependencies:
```bash
pip install kivy qrcode pillow opencv-python pyzbar
