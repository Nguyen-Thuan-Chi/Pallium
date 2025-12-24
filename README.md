# Pallium 🛡️ - Zero-Knowledge Password Vault

> **"Your keys never leave this device."**

Pallium is a secure, **Zero-Knowledge Architecture** password manager designed to demonstrate the principles of client-side encryption. Unlike traditional password managers, Pallium ensures that the server **never** sees your master password or your stored credentials in plain text.

![Pallium Demo](https://via.placeholder.com/800x400?text=Pallium+Dashboard+Preview)

## 🚀 Key Features

* **Zero-Knowledge Architecture:** The server only stores encrypted blobs (Ciphertext) and the Initialization Vector (IV). It has zero knowledge of the actual data.
* **Client-Side Encryption:** All encryption/decryption happens in the browser using the **Web Crypto API**.
* **AES-256-GCM:** Industry-standard military-grade encryption for all vault items.
* **PBKDF2 Key Derivation:** The Master Key is derived from the user's password using PBKDF2 (SHA-256) with high iteration counts, existing only in the device's volatile memory (RAM).
* **Secure Authentication:** JWT-based authentication flow (OAuth2 compatible).
* **Demo Mode:** "Show Encrypted Data" toggle to visualize the underlying ciphertext for educational purposes.

## 🛠️ Tech Stack

### Frontend
* **Core:** Vanilla JavaScript (ES6 Modules) - No heavy frameworks, pure logic.
* **Cryptography:** Web Crypto API (SubtleCrypto).
* **UI/Styling:** TailwindCSS (via CDN).

### Backend
* **Framework:** FastAPI (Python).
* **Database:** SQLite (SQLAlchemy ORM).
* **Security:** `passlib` (Argon2/Bcrypt) for user authentication.

## 🏗️ Architecture Flow

1.  **Login:** User enters `username` + `password`.
2.  **Key Gen:** Browser derives `MasterKey` using PBKDF2. **This key is never sent to the network.**
3.  **Auth:** Browser sends hashed credentials to get a `JWT Token`.
4.  **Encryption (Save):**
    * Payload (User/Pass) -> JSON -> `AES-256-GCM` -> `Ciphertext` + `IV`.
    * Send `Ciphertext` + `IV` to API.
5.  **Decryption (Load):**
    * Fetch `Ciphertext` + `IV` from API.
    * Decrypt using `MasterKey` in RAM -> Show plaintext.

## 📦 Installation & Setup

### Prerequisites
* Python 3.9+
* A modern browser (Chrome/Edge/Firefox).

### 1. Backend Setup
```bash
# Navigate to backend folder
cd backend

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn app.main:app --reload --port 8000

API Documentation available at: http://127.0.0.1:8000/docs
2. Frontend Setup

Since the frontend uses ES6 Modules, it must be served via a local server (not file://).
Bash

# Navigate to project root
cd .

# Start a simple HTTP server
python3 -m http.server 5500

3. Usage

    Open http://127.0.0.1:5500 in your browser.

    Login: Use admin / password (or create a new user via Swagger UI).

    Add Item: Click + New Item, enter details, and click Encrypt & Save.

    Verify: Toggle the "Show Encrypted Data" checkbox to see what the server actually holds.

    Security Check: Refresh the page (F5). You will be logged out because the Master Key (RAM) is wiped.

⚠️ Disclaimer

This project is for educational and academic purposes. While it uses standard cryptographic algorithms, it has not undergone a third-party security audit.