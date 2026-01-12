// --- Globale variables ---
let socket;
let chatKey; // local AES-Key for encryption
let isLoginMode = true;

const PORT = process.env.PORT;

// --- 1. CRYPTOGRAPHIE (Web Crypto API) ---

/**
 * Generates a stable AES key from the chat password.
 */
async function deriveKey(password) {
    const enc = new TextEncoder();
    // The ‘salt’ should be unique per user in a real application
    // Here I use a fixed salt is used for simplicity
    const salt = enc.encode("super-secret-salt");

    const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(password),
        "PBKDF2", false, ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false, ["encrypt", "decrypt"]
    );
}

/**
* Encrypts text using the AES key. 
*/
async function encryptData(text, key) {
    const enc = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12)); // Initialisierungsvektor
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        enc.encode(text)
    );

    return {
        // Convert binary data to Base64 strings for sending
        cipherText: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
        iv: btoa(String.fromCharCode(...iv))
    };
}

/**
 * Decrypts the received data.
 */
async function decryptData(cipherObject, key) {
    const iv = new Uint8Array(atob(cipherObject.iv).split("").map(c => c.charCodeAt(0)));
    const cipherText = new Uint8Array(atob(cipherObject.cipherText).split("").map(c => c.charCodeAt(0)));

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        cipherText
    );

    return new TextDecoder().decode(decrypted);
}

// --- 2. AUTHENTICATION ---

/**
 * Switch between login and registration in the UI.
 */
function toggleAuthMode() {
    isLoginMode = !isLoginMode;
    document.getElementById('auth-title').innerText = isLoginMode ? "Login" : "Register";
    document.getElementById('main-auth-btn').innerText = isLoginMode ? "Login" : "Create Account";
    document.getElementById('toggle-btn').innerText = isLoginMode ? "No account yet? Register" : "Back to login";
}

/**
 * Sends login or registration data to the server.
 */
async function handleAuth() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const chatPassword = document.getElementById('chat-password').value;

    if (!username || !password || !chatPassword) {
        return alert("Please complete all fields!");
    }

    const endpoint = isLoginMode ? '/login' : '/register';

    try {
        const response = await fetch(`http://localhost:${PORT}/${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText);
        }

        if (isLoginMode) {
            const { token } = await response.json();
            
            // 1. Derive chat key locally from password
            chatKey = await deriveKey(chatPassword);
            
            // 2. Start socket connection with JWT
            connectSocket(token, username);
        } else {
            alert("Registration successful! Please log in now.");
            toggleAuthMode();
        }
    } catch (err) {
        alert("Error: " + err.message);
    }
}

// --- 3. SOCKET & CHAT LOGIC ---

/**
 * Establishes the WebSocket connection.
 */
function connectSocket(token, myUsername) {
    socket = io(`http://localhost:${PORT}`, {
        auth: { token }
    });

    socket.on('connect', () => {
        console.log("Connected as:", myUsername);
        document.getElementById('auth-container').style.display = 'none';
        document.getElementById('chat-container').style.display = 'flex';
    });

    socket.on('receive-message', async (data) => {
        try {
            // Decrypt message with local key
            const decryptedText = await decryptData(data.content, chatKey);
            displayMessage(data.fromUserId, decryptedText, 'other');
        } catch (e) {
            displayMessage("SYSTEM", "[Received encrypted message - key incorrect]", 'other');
        }
    });

    socket.on('connect_error', (err) => {
        alert("Socket error: " + err.message);
    });
}

/**
 * Encrypts and sends a message.
 */
async function sendMessage() {
    const targetId = document.getElementById('target-id').value;
    const text = document.getElementById('msg-input').value;

    if (!text || !targetId) return alert("Enter destination and message!");

    // Encrypt message locally
    const encrypted = await encryptData(text, chatKey);

    socket.emit('send-message', {
        toUserId: targetId,
        encryptedContent: encrypted
    });

    displayMessage('ME', text, 'me');
    document.getElementById('msg-input').value = '';
}

/**
 *  Shows Messages in the chat window.
 */
function displayMessage(sender, text, type) {
    const chatWindow = document.getElementById('chat-window');
    const div = document.createElement('div');
    div.className = `msg ${type}`;
    div.innerHTML = `<strong>${sender}:</strong> ${text}`;
    chatWindow.appendChild(div);
    chatWindow.scrollTop = chatWindow.scrollHeight; // Auto-Scroll down
}