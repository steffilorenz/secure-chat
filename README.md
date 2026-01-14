## E2EE Secure Chat 🔐

A simple real-time chat demonstrating End-to-End Encryption (E2EE).

### Tech Stack

- Frontend: HTML5, CSS3, JavaScript (Web Crypto API)
- Backend: Node.js, Express.js
- Real-time: Socket.io
- Security: JSON Web Tokens (JWT), Bcrypt, Dotenv

### Installation & Setup

1. Clone the repository:

   ```
   git clone https://github.com/steffilorenz/secure-chat.git
   cd secure-chat
   ```

2. Install dependencies:

   ```
   npm install
   ```

3. Environment Configuration: Create a .env file in the root directory and add your secret:

   ```
   JWT_SECRET=your_super_secret_key_here
   PORT=3000
   ```

4. Start the server:

   ```
   npm start
   ```

5. Access the App: Open http://localhost:3000 in at least two browser windows to demonstrate the chat.

6. In each window, register a user account and sign in using the same chat-key in both sessions, then start chatting.

### Core Features

- Zero-Knowledge: The server never sees your plain messages or your chat keys.
- Encryption: Local AES-256-GCM encryption via Web Crypto API.
- Key Derivation: PBKDF2 (100k iterations) for secure key generation.
- Auth: Secure Login with JWT and bcrypt password hashing.

### Security Architecture

##### Key Derivation & Encryption

- The user enters a Chat-Key (different from the login password).
- The Web Crypto API uses PBKDF2 to transform this string into a high-entropy 256-bit key.
- Every message is encrypted with a unique Initialization Vector (IV).
- The server receives only the ciphertext and the IV. It never sees the plaintext or the Chat-Key.

##### Authentication

- Users register and log in via an Express API.
- Passwords are never stored in plain text; only bcrypt hashes are saved to users.json.
- Authenticated requests are protected by JWT stored in the session.

##### Verification: Key Fingerprinting

To ensure that both chat participants have derived the exact same cryptographic key without ever sending the key over the network, this application implements "Key Fingerprinting".

### Development & AI Disclosure

The code was generated with the help of AI tools (Claude & Gemini) and customized according to my own specifications and requirements.

### License

This project is licensed under the MIT License.
