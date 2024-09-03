# Encryption Decryption App with 2FA

This Python application provides a simple GUI-based tool for encrypting and decrypting text messages using a password and Two-Factor Authentication (2FA). It uses AES encryption with GCM mode for security and integrates TOTP (Time-Based One-Time Password) for an additional layer of protection.

## Features

- **AES Encryption & Decryption**: Secure messages with AES encryption in GCM mode.
- **Password-Based Encryption**: Derive encryption keys using a user-provided password.
- **Two-Factor Authentication (2FA)**: Adds security by requiring a TOTP code during encryption and decryption.
- **GUI Interface**: A simple graphical interface for easy usage.

## Prerequisites

Before running the application, ensure you have the following Python packages installed:

- `tkinter`: For the graphical interface.
- `cryptography`: For cryptographic functions.
- `pyotp`: For generating and verifying TOTP codes.

You can install the required packages using pip:

```bash
pip install cryptography pyotp
