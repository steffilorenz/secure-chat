// --- Globale Variablen ---
let socket;
let chatKey; // Der lokale AES-Schlüssel für die Verschlüsselung
let isLoginMode = true;

const PORT = process.env.PORT;

// --- 1. KRYPTOGRAPHIE (Web Crypto API) ---

/**
 * Erzeugt einen stabilen AES-Schlüssel aus dem Chat-Passwort.
 */
async function deriveKey(password) {
    const enc = new TextEncoder();
    // Das "Salz" sollte in einer echten App pro User einzigartig sein. 
    // Hier nutzen wir ein festes Salz für die Einfachheit.
    const salt = enc.encode("mein-super-sicheres-festes-salz");

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
 * Verschlüsselt einen Text mit dem AES-Schlüssel.
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
        // Wir konvertieren die Binärdaten in Base64-Strings für den Versand
        cipherText: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
        iv: btoa(String.fromCharCode(...iv))
    };
}

/**
 * Entschlüsselt die empfangenen Daten.
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

// --- 2. AUTHENTIFIZIERUNG ---

/**
 * Wechselt zwischen Login und Registrierung im UI.
 */
function toggleAuthMode() {
    isLoginMode = !isLoginMode;
    document.getElementById('auth-title').innerText = isLoginMode ? "Login" : "Registrieren";
    document.getElementById('main-auth-btn').innerText = isLoginMode ? "Einloggen" : "Konto erstellen";
    document.getElementById('toggle-btn').innerText = isLoginMode ? "Noch kein Konto? Registrieren" : "Zurück zum Login";
}

/**
 * Sendet Login- oder Registrierungsdaten an den Server.
 */
async function handleAuth() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const chatPassword = document.getElementById('chat-password').value;

    if (!username || !password || !chatPassword) {
        return alert("Bitte alle Felder ausfüllen!");
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
            
            // 1. Chat-Key lokal aus dem Passwort ableiten
            chatKey = await deriveKey(chatPassword);
            
            // 2. Socket-Verbindung mit JWT starten
            connectSocket(token, username);
        } else {
            alert("Registrierung erfolgreich! Bitte logge dich jetzt ein.");
            toggleAuthMode();
        }
    } catch (err) {
        alert("Fehler: " + err.message);
    }
}

// --- 3. SOCKET & CHAT LOGIK ---

/**
 * Baut die WebSocket-Verbindung auf.
 */
function connectSocket(token, myUsername) {
    socket = io(`http://localhost:${PORT}`, {
        auth: { token }
    });

    socket.on('connect', () => {
        console.log("Verbunden als:", myUsername);
        document.getElementById('auth-container').style.display = 'none';
        document.getElementById('chat-container').style.display = 'flex';
    });

    socket.on('receive-message', async (data) => {
        try {
            // Nachricht mit lokalem Schlüssel entschlüsseln
            const decryptedText = await decryptData(data.content, chatKey);
            displayMessage(data.fromUserId, decryptedText, 'other');
        } catch (e) {
            displayMessage("SYSTEM", "[Verschlüsselte Nachricht empfangen - Schlüssel inkorrekt]", 'other');
        }
    });

    socket.on('connect_error', (err) => {
        alert("Socket Fehler: " + err.message);
    });
}

/**
 * Verschlüsselt und sendet eine Nachricht.
 */
async function sendMessage() {
    const targetId = document.getElementById('target-id').value;
    const text = document.getElementById('msg-input').value;

    if (!text || !targetId) return alert("Ziel und Nachricht eingeben!");

    // Nachricht lokal verschlüsseln
    const encrypted = await encryptData(text, chatKey);

    socket.emit('send-message', {
        toUserId: targetId,
        encryptedContent: encrypted
    });

    displayMessage('Ich', text, 'me');
    document.getElementById('msg-input').value = '';
}

/**
 * Zeigt Nachrichten im Chat-Fenster an.
 */
function displayMessage(sender, text, type) {
    const chatWindow = document.getElementById('chat-window');
    const div = document.createElement('div');
    div.className = `msg ${type}`;
    div.innerHTML = `<strong>${sender}:</strong> ${text}`;
    chatWindow.appendChild(div);
    chatWindow.scrollTop = chatWindow.scrollHeight; // Auto-Scroll nach unten
}