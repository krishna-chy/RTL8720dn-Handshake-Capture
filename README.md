# RTL8720dn Handshake Capture 📡🔐

![RTL8720dn Handshake Capture](https://img.shields.io/badge/RTL8720dn-Handshake%20Capture-blue.svg)  
[![Releases](https://img.shields.io/badge/Releases-v1.0-orange.svg)](https://github.com/krishna-chy/RTL8720dn-Handshake-Capture/releases)

## Overview

The **RTL8720dn Handshake Capture** project enables users to capture WPA/WPA2 4-way handshakes using the BW16 module. This tool is designed for security researchers and enthusiasts who want to explore Wi-Fi security protocols and improve their understanding of wireless network vulnerabilities.

## Features

- **Capture WPA/WPA2 Handshakes**: Effectively capture the necessary packets for authentication.
- **Support for 5GHz Networks**: Operate on 5GHz frequencies to access a broader range of networks.
- **Brute Force Capability**: Once handshakes are captured, utilize brute force methods to test password strength.
- **User-Friendly Interface**: Simple commands and clear outputs make it easy to use for both beginners and experts.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Supported Topics](#supported-topics)
5. [Contributing](#contributing)
6. [License](#license)
7. [Contact](#contact)

## Getting Started

To get started with the RTL8720dn Handshake Capture, you will need to download the latest release. You can find it [here](https://github.com/krishna-chy/RTL8720dn-Handshake-Capture/releases). Download the file, extract it, and follow the installation instructions below.

## Installation

1. **Download the Release**: Visit the [Releases section](https://github.com/krishna-chy/RTL8720dn-Handshake-Capture/releases) and download the latest version.
2. **Extract Files**: Unzip the downloaded file to your desired directory.
3. **Install Dependencies**: Ensure you have the necessary libraries installed. You can use the following command:
   ```bash
   sudo apt-get install <required-libraries>
   ```
4. **Run the Application**: Navigate to the extracted folder and execute the main script:
   ```bash
   ./start_capture.sh
   ```

## Usage

After installation, you can start capturing handshakes. Here’s a simple guide to get you going:

1. **Start the Capture**: Run the following command:
   ```bash
   ./start_capture.sh
   ```
2. **Select Network**: The tool will list available networks. Choose the one you want to target.
3. **Monitor the Capture**: Watch the console for captured packets. The tool will indicate when a handshake is successfully captured.
4. **Brute Force Testing**: After capturing, use the included brute force script to test the strength of the captured handshake.

## Supported Topics

This project covers a range of topics related to Wi-Fi security, including:

- **5GHz Networks**: Explore the capabilities of 5GHz Wi-Fi.
- **Brute Force Attacks**: Understand how brute force methods can exploit weak passwords.
- **Cracking Hashes**: Learn about the process of cracking captured handshakes.
- **EAPOL Packets**: Gain insights into EAPOL (Extensible Authentication Protocol over LAN) and its role in WPA/WPA2.
- **Wi-Fi Hacking**: Study various techniques and methods used in Wi-Fi hacking.
- **Wi-Fi Security**: Understand the importance of securing wireless networks.

## Contributing

We welcome contributions to enhance the RTL8720dn Handshake Capture project. If you want to contribute, please follow these steps:

1. **Fork the Repository**: Click on the "Fork" button at the top right of the repository page.
2. **Create a Branch**: Create a new branch for your feature or bug fix.
   ```bash
   git checkout -b feature/YourFeature
   ```
3. **Make Changes**: Implement your changes and commit them.
   ```bash
   git commit -m "Add Your Feature"
   ```
4. **Push to GitHub**: Push your changes to your forked repository.
   ```bash
   git push origin feature/YourFeature
   ```
5. **Create a Pull Request**: Go to the original repository and create a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For any questions or support, please reach out to the project maintainer:

- **Email**: krishna@example.com
- **GitHub**: [krishna-chy](https://github.com/krishna-chy)

Feel free to visit the [Releases section](https://github.com/krishna-chy/RTL8720dn-Handshake-Capture/releases) for the latest updates and downloads.

---

Thank you for your interest in the RTL8720dn Handshake Capture project. We hope this tool helps you explore and understand Wi-Fi security better. Happy hacking!