# Chat P2P

## Overview
Chat P2P is a peer-to-peer (P2P) messaging application designed to provide secure and efficient communication between users. The application leverages advanced cryptographic techniques and a robust database structure to ensure data integrity, confidentiality, and seamless user experience.

## Features
- **Peer-to-Peer Messaging**: Direct communication between peers without relying on centralized servers.
- **End-to-End Encryption**: Messages are encrypted using AES and ECC algorithms to ensure privacy.
- **Secure Key Exchange**: Ephemeral keys are used for secure key exchanges.
- **Database Management**: SQLite database for storing peer information, chat history, and pending messages.
- **Handshake Protocol**: Secure initialization of communication channels between peers.

## Components

### 1. `chat_p2p.py`
This is the main module that handles the core functionality of the P2P chat application.
- **Classes**:
  - `Chat`: Manages peer connections, message sending/receiving, and cryptographic operations.
- **Key Functions**:
  - `send_message`: Sends encrypted messages to peers.
  - `dispatcher`: Routes incoming messages to appropriate handlers.
  - `exchange_handler`: Handles secure key exchanges.
  - `handshake_handler`: Manages the handshake process for initializing secure communication.

### 2. `udp_plus.py`
This module provides the UDP-based communication layer for the application.
- **Classes**:
  - `UDP_Plus`: Implements reliable UDP communication with support for message chunking, retries, and acknowledgments.
- **Key Functions**:
  - `udp_receiver`: Listens for incoming UDP packets and processes them.
  - `message_sender`: Sends messages, splitting them into chunks if necessary.
  - `put_message`/`get_message`: API for sending and receiving messages.
  - `recompose_message`: Reassembles message chunks into the original message.

### 3. `cipher.py`
This module provides cryptographic utilities for encryption, decryption, signing, and verification.
- **Classes**:
  - `AES`: Implements AES-GCM-SIV encryption and decryption.
  - `ECC`: Implements Elliptic Curve Cryptography for key generation, signing, and verification.
- **Key Functions**:
  - `derive_key`: Derives a 256-bit key from a password using Argon2id.
  - `encrypt`/`decrypt`: Encrypts and decrypts data using AES-GCM-SIV.
  - `gen_keypair`: Generates ECC key pairs.
  - `sign`/`verify`: Signs and verifies data using ECC.

### 4. `db.py`
This module manages the SQLite database for storing peer and chat information.
- **Classes**:
  - `ChatDB`: Handles database operations such as creating tables, inserting, updating, and deleting records.
- **Key Functions**:
  - `create_tables`: Creates tables for peers, chats, pending messages, and handshakes.
  - `get_peers`: Retrieves peer information.
  - `update_chat`: Updates chat history in the database.
  - `set_pending`: Stores pending messages for offline peers.
  - `set_primary_key`: Manages handshake keys.

## Cryptographic Details
- **AES-GCM-SIV**: Provides authenticated encryption with associated data (AEAD) to ensure data integrity and confidentiality.
- **Elliptic Curve Cryptography (ECC)**: Used for secure key exchanges and digital signatures.
- **Argon2id**: A memory-hard key derivation function to protect against brute-force attacks.

## Database Schema
- **Peers Table**: Stores peer information (ID, nickname, address, keys, etc.).
- **Chats Table**: Stores chat messages with timestamps.
- **Pending Table**: Stores messages for offline delivery.
- **Handshakes Table**: Stores handshake keys and expiration times.

## How to Run
1. Clone the repository:
   ```bash
   git clone https://github.com/AutoRobotix/Chat-P2P.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Chat-P2P
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:
   ```bash
   python chat_p2p.py
   ```

## Future Enhancements
- Implement a graphical user interface (GUI) for better user experience.
- Add support for file sharing between peers.
- Enhance error handling and logging mechanisms.

## License
This project is licensed under the GPL License. See the LICENSE file for details.

## Acknowledgments
- [Cryptography Library](https://cryptography.io/) for providing robust cryptographic primitives.
- SQLite for lightweight database management.
