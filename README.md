# Identity-Based Encryption (IBE) with Boneh-Franklin Scheme in Python

This project implements the Boneh-Franklin Identity-Based Encryption (IBE) scheme using elliptic curve cryptography and AES. It enables secure communication using identities (e.g., email addresses) as public keys, eliminating the need for traditional public key infrastructure (PKI).

---

## Features

- Identity-based key generation and encryption
- AES-based secure message encryption/decryption
- ECC (P-256 curve) for identity-to-key derivation
- Server-client architecture for secure messaging
- Performance tracking (key extraction, encryption, decryption times)
- Debug mode for tracing internal cryptographic operations

---

## Technologies Used

- Python 3.x
- ECC (Elliptic Curve Cryptography)
- AES (Advanced Encryption Standard)
- `pycryptodome` for cryptographic operations
- Socket programming for client-server communication

---

## Setup Instructions

1. **Install Dependencies**

   ```bash
   pip install pycryptodome
2. **Start the Server (Private Key Generator - PKG)**
   ```bash
   python server.py
3. **Run the Client**
   ```bash
   python client.py
You will be prompted to enter your identity (e.g., email address).

## Project Structure
- **server.py:** Implements the Private Key Generator (PKG) for identity registration and key issuance.
- **client.py:** Handles identity registration, message encryption, decryption, and user commands.
  
## Performance Evaluation
The system tracks and logs:
- Key extraction time (server)
- Encryption and decryption times (client)
- Type stats in the client terminal to view these metrics.

## Security Considerations
- Relies on well-known ECC and AES security assumptions
- Eliminates the need for digital certificates
- Simplified implementation for educational/demo purposes only — not production-ready

