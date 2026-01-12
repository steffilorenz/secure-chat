require('dotenv').config(); // Lädt die Variablen aus der .env Datei

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const USERS_FILE = './users.json';

const app = express();

const server = http.createServer(app);
const io = new Server(server);

const SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT;
let users = loadUsers(); // load users from users.json

app.use(express.json());

// Serve the frontend directly from the server to avoid CORS
app.use(express.static(path.join(__dirname, '..','public')));


// --- AUTH ROUTEN ---
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;

    if (users.find(u => u.username === username)) 
        return res.status(400).send("User already exist");

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { username, password: hashedPassword };

    // 1. push new user into global array (update RAM)
    users.push(newUser);

    // 2. write user into the json (update)
    saveUsers(users);

    res.status(201).send("Registration successful");
});    

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ userId: username }, SECRET);
        return res.json({ token });
    }    
    res.status(401).send("login error");
});    


io.use((socket, next) => {
// --- SOCKET LOGIK ---
    const token = socket.handshake.auth.token;
    try {
        const decoded = jwt.verify(token, SECRET);
        socket.userId = decoded.userId;
        next();
    } catch (err) { next(new Error("Auth error")); }
});

io.on('connection', (socket) => {
    socket.join(socket.userId);
    socket.on('send-message', (data) => {
        console.log("\n--- SERVER-LOG (INTERCEPTED PAKET) ---");
        console.log("Sender ID:", socket.userId);
        console.log("Recipient ID:", data.toUserId);
        console.log("Encrypted content (ct):", data.encryptedContent.ct); 
        console.log("Initialisation vector (iv):", data.encryptedContent.iv); 
        console.log("---------------------------------------\n");

        io.to(data.toUserId).emit('receive-message', {
            fromUserId: socket.userId,
            content: data.encryptedContent
        });
    });
});

server.listen(PORT, () => console.log(`Server is running: http://localhost:${PORT}`));


// --- SUPPORT FUNCTIONS ---

function loadUsers() {
    if (!fs.existsSync(USERS_FILE)) return [];
    const data = fs.readFileSync(USERS_FILE);
    return JSON.parse(data);
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}