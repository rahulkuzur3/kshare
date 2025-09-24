<div align="center">
  <img src="https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhl8lkARlEO5dtky5n-8BDvjv6vPpnqKEcdaT70wagSr5MDWSCBifFqL55q8DdRbgj0dOJDKRrCjUntVg3kxk55aGJA0ZqCUDxdgODo8qSKtafLHgLphtZARq86l7b_5n-iyB32lCksWKEs0qpdaDXRV1xmSP8y6LPpMYPONaNcdvXz7dakKuyhOkMzr1NJ/s320/1000018855.jpg" alt="KShare Logo" width="150"/>
  <h1>KShare ⚡</h1>
  <p><strong>Your Private, Cross-Platform File & Folder Sharing Hub</strong></p>

  <p>
    <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.7+-blue.svg" alt="Python Version"></a>
    <a href="https://github.com/your-username/kshare/blob/master/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"></a>
    <a href="#"><img src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Android-brightgreen" alt="Platform"></a>
  </p>
</div>

---

*KShare* is a powerful, privacy-focused file sharing application designed for the modern world. It allows you to effortlessly transfer files and folders of any size between your devices—be it *Windows, macOS, Linux, or Android*. The core philosophy is simple: your data is yours. KShare operates entirely on your local network, meaning your files are never sent to the cloud or an external server. This ensures lightning-fast speeds and absolute privacy.

Whether you're a developer sending a project folder to your phone, a designer sharing assets with a colleague across the room, or just sending vacation photos to your laptop, KShare makes it secure, simple, and fast.

## Table of Contents

- [Core Features](#-core-features)
- [Demonstration](#-demonstration)
- [Installation Guide](#-installation-guide)
  - [For End-Users (Recommended)](#for-end-users-recommended)
  - [For Developers (From Source)](#for-developers-from-source)
- [How to Use KShare](#-how-to-use-kshare)
- [Technical Deep Dive & Project Architecture](#-technical-deep-dive--project-architecture)
  - [Networking Protocol](#networking-protocol)
  - [Device Discovery](#device-discovery)
  - [Security & Encryption](#security--encryption)
  - [Folder Sharing Mechanism](#folder-sharing-mechanism)
  - [Cross-Platform Strategy](#cross-platform-strategy)
- [Building the Application from Source](#-building-the-application-from-source)
  - [Building for Desktop (Windows & macOS)](#building-for-desktop-windows--macos)
  - [Building for Android](#building-for-android)
- [How to Contribute](#-how-to-contribute)
- [Future Roadmap](#-future-roadmap)
- [License](#-license)
- [Acknowledgments](#-acknowledgments)

## ✨ Core Features

*   🖥 *Truly Cross-Platform:* A single, unified experience. Share files between a Windows PC, a MacBook, a Linux machine, and an Android phone without any compatibility issues.

*   🌐 *100% Offline & Local:* Operates entirely on your local Wi-Fi or a personal hotspot. Your data never leaves your network, guaranteeing privacy and maximum transfer speed.

*   🔮 *Zero-Configuration Discovery:* No more fumbling with IP addresses. KShare uses the *Zeroconf (Bonjour/Avahi)* protocol to automatically discover other devices on the network. They just appear in your list.

*   🔒 *Peace of Mind with AES-256 Encryption:* Every file and folder is protected with industry-standard *AES-256 (CBC mode)* end-to-end encryption. A unique password set for each transfer ensures only the intended recipient can access the data.

*   📂 *Seamless Folder Transfers:* Select an entire folder and KShare will transparently compress it, send it, and decompress it on the other side, perfectly preserving the original directory structure.

*   🚀 *Lightweight and Fast:* Built with efficiency in mind. The application is lightweight, and the direct peer-to-peer connection maximizes your network's bandwidth for rapid transfers of large files.

## 🎞 Demonstration

Here is a typical workflow, sending a project folder from a Windows desktop to an Android device.

![Demo GIF Placeholder](https://user-images.githubusercontent.com/10248436/141972522-2900c280-1a11-471d-a417-0b1a13621575.gif)

1.  Both devices are on the same Wi-Fi.
2.  The Android device appears automatically on the Windows app.
3.  The user selects the Android device, clicks "Send Folder", and chooses a folder.
4.  A password is set for the transfer.
5.  The Android user is prompted for the same password to authorize the download.
6.  The encrypted folder is transferred, decrypted, and extracted to the phone's "Downloads" folder.

## 📦 Installation Guide

### For End-Users (Recommended)

This is the easiest way to get started. No programming knowledge required.

1.  Navigate to the *[Releases Page](https://github.com/your-username/kshare/releases)* for this project.
2.  Under the latest release, download the appropriate file for your system:
    *   For *Windows*: KShare.exe
    *   For *macOS*: KShare.dmg or KShare.app.zip
    *   For *Android*: KShare.apk
3.  *On Desktop*: Double-click the application to run it. You may need to grant it firewall access on first launch.
4.  *On Android*: Copy the .apk to your phone and install it. You must "Allow installation from unknown sources" in your phone's security settings.

### For Developers (From Source)

This method allows you to run, modify, and build the project yourself.

1.  *Prerequisites:*
    *   Python 3.7+
    *   Git

2.  *Clone the Repository:*
    bash
    git clone https://github.com/your-username/kshare.git
    cd kshare
    

3.  *Set up a Virtual Environment:*
    bash
    python -m venv venv
    # On Windows:
    venv\Scripts\activate
    # On macOS/Linux:
    source venv/bin/activate
    

4.  *Install Dependencies:*
    A requirements.txt file should be created containing:
        cryptography
    zeroconf
    ifaddr
    kivy
    plyer
    pyinstaller # For building
    buildozer   # For building
    
    Then run:
    bash
    pip install -r requirements.txt
    

5.  *Run the App:*
    *   *Desktop Version:* python kshare_final.py
    *   *Android Version:* python main.py (for desktop testing) or follow the build instructions below.

## 📖 How to Use KShare

1.  *Connect to Wi-Fi:* Ensure all devices are connected to the same Wi-Fi network.
2.  *Launch KShare:* Open the KShare application on all devices you wish to share between.
3.  *Wait for Discovery:* Within a few seconds, the names of other devices (e.g., "KShare on My-Laptop") will automatically appear in the list.
4.  *Initiate Transfer:*
    *   On the device you're sending from, click the name of the destination device in the list to select it.
    *   Click either the *"Send File"* or *"Send Folder"* button.
    *   A file/folder selection dialog will open. Choose your content.
5.  *Set Password:* You will be prompted to enter a password for this specific transfer. This password encrypts your data.
6.  *Authorize Reception:* On the receiving device, a prompt will appear asking for the password you just set. Enter the same password to begin the transfer.
7.  *Done!* The content will be securely transferred and saved to the application's directory (or "Downloads" on Android).

## 🔬 Technical Deep Dive & Project Architecture

This project integrates several key technologies to deliver a seamless experience.

#### Networking Protocol
-   *Transport:* The application uses *TCP Sockets* for reliable, ordered data transfer. A simple server is started on a background thread in each app instance on port 5001 to listen for incoming connections.
-   *Metadata:* Before the file data is sent, a small header containing the filename and filesize (filename<SEPARATOR>filesize) is sent. For encrypted transfers, a randomly generated 16-byte Initialization Vector (IV) is sent immediately after the metadata.

#### Device Discovery
-   *Protocol:* To avoid manual IP entry, the app uses *Zeroconf (mDNS)* via the zeroconf Python library.
-   *Mechanism:*
    1.  *Advertising:* On startup, each KShare instance registers a service of type _kshare._tcp.local. on the network, advertising its hostname, IP address, and listening port.
    2.  *Browsing:* Simultaneously, each instance browses for other services of the same type.
    3.  *UI Update:* A ServiceListener updates the GUI in real-time as devices are added or removed from the network, providing the seamless discovery experience.

#### Security & Encryption
-   *Algorithm:* Data is encrypted using *AES (Advanced Encryption Standard)* in *CBC (Cipher Block Chaining)* mode with a 256-bit key.
-   *Key Derivation:* The user-provided password is not used directly as the key. Instead, it is passed through the *SHA-256* hashing algorithm to derive a secure, fixed-size 32-byte (256-bit) key. This protects against weak passwords.
-   *Padding:* *PKCS7 padding* is used to ensure that the final block of data sent to the encryptor is always the correct size for AES.
-   *IV (Initialization Vector):* A new, cryptographically secure 16-byte IV is generated for every single transfer. This ensures that sending the same file with the same password results in a different encrypted output, preventing pattern analysis attacks.

#### Folder Sharing Mechanism
-   To simplify the transfer of complex directory structures, the application uses a zip-on-the-fly approach:
    1.  The user selects a folder to send.
    2.  The app uses Python's shutil.make_archive to compress the entire folder into a temporary .zip file.
    3.  This single .zip file is then transferred using the standard encrypted file transfer protocol. The filename is prefixed with FOLDER_ZIP_ to signal its type.
    4.  The receiving client decrypts the .zip file and, upon recognizing the prefix, uses zipfile.extractall to decompress its contents into a new folder.
    5.  The temporary .zip files on both ends are deleted.

#### Cross-Platform Strategy
-   *Desktop (Windows, macOS, Linux):* The GUI is built with Tkinter, Python's standard GUI package. This ensures maximum compatibility and no need for external UI library installations on most systems.
-   *Mobile (Android):* The app is ported to the *Kivy* framework. While the core networking and encryption logic remains the same, the UI is rewritten with Kivy widgets. *Plyer* is used as an abstraction layer to access native Android APIs like the file chooser and storage permissions.

## 🏗 Building the Application from Source

### Building for Desktop (Windows & macOS)

We use *PyInstaller* to create single-file executables.

1.  *Install PyInstaller:* pip install pyinstaller
2.  *(Optional)* Get an icon file (icon.ico for Windows, icon.icns for macOS) and place it next to the script.
3.  *Run the build command* from the project's root directory:

    *On Windows:*
    bash
    pyinstaller --onefile --windowed --name KShare --icon=icon.ico kshare_final.py
    
    *On macOS:*
    bash
    pyinstaller --onefile --windowed --name KShare --icon=icon.icns kshare_final.py
    
4.  Find your standalone application in the dist/ folder.

### Building for Android

We use *Buildozer* to create the APK. This process *must be run on Linux or macOS (or WSL on Windows)*.

1.  *Install Buildozer:* pip install buildozer
2.  *Initialize the project:* Navigate to the folder containing main.py and run:
    bash
    buildozer init
    
3.  **Configure buildozer.spec:**
    *   Set title, package.name, and package.domain.
    *   In the requirements line, add all necessary libraries: python3,kivy,cryptography,plyer.
    *   Add Android permissions: android.permissions = INTERNET, READ_EXTERNAL_STORAGE, ACCESS_NETWORK_STATE.
4.  *Run the build:*
    bash
    buildozer android debug
    
5.  Find your KShare-0.1-debug.apk in the bin/ folder.

## 🤝 How to Contribute

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are *greatly appreciated*.

1.  *Fork the Project*
2.  *Create your Feature Branch* (git checkout -b feature/AmazingFeature)
3.  *Commit your Changes* (git commit -m 'Add some AmazingFeature')
4.  *Push to the Branch* (git push origin feature/AmazingFeature)
5.  *Open a Pull Request*

Please open an issue first to discuss any major changes you would like to make.

## 🗺 Future Roadmap

-   [ ] *Modern UI with PyQt6:* Migrate the desktop application to the Qt framework for a more professional look, native widgets, and advanced features like drag-and-drop.
-   [ ] *Wi-Fi Direct / Hotspot Mode:* Implement a feature to create a software hotspot directly from the app, removing the need for an external router.
-   [ ] *Multi-File & Queue Transfers:* Select multiple files at once and see them in a transfer queue with individual progress.
-   [ ] *QR Code Connection:* Generate a QR code on the receiver that the sender can scan to instantly establish a connection.
-   [ ] *Clipboard Sharing:* Add an option to share the contents of your clipboard (text and images) between devices.

## 📜 License

This project is distributed under the MIT License. See the LICENSE.md file for more information.

## 🙏 Acknowledgments

*   The Python Software Foundation
*   The Kivy & Buildozer teams
*   The developers of the many open-source libraries that made this possible.

---
