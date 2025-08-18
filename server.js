const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const http = require('http');
const { Server } = require('socket.io');

dotenv.config();
const app = express();
const server = http.createServer(app);

// Middleware
app.use(express.json());
app.use(cors({
  origin: ['http://localhost:5173', 'https://editior.vercel.app'], // allow local dev + Vercel frontend
  credentials: true
}));
app.use(require('./config/session'));

// Routes (keep same route paths as original)
app.use('/api/admin', require('./routes/admin'));
app.use('/api', require('./routes/auth'));
app.use('/api', require('./routes/users'));
app.use('/api', require('./routes/passwordReset'));
app.use('/api', require('./routes/codeExec'));
app.use('/api', require('./routes/projects'));

// Socket.IO
const io = new Server(server, {
  cors: {
    origin: ['http://localhost:5173', 'https://editior.vercel.app'],
    methods: ['GET', 'POST'],
    credentials: true
  }
});
require('./socket/collaboration')(io);

// Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
