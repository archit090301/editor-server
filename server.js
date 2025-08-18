// index.js
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const http = require('http');
const { Server } = require('socket.io');

dotenv.config();
const app = express();
const server = http.createServer(app);

// Allowed origins
const allowedOrigins = [
  'http://localhost:5173',          // local dev
  'https://editior.vercel.app'      // deployed frontend
];

// Middleware
app.use(express.json());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

// Session middleware
app.use(require('./config/session')); // ensure cookie: { secure: true, sameSite: 'none' } in production

// Routes
app.use('/api/admin', require('./routes/admin'));
app.use('/api', require('./routes/auth'));
app.use('/api', require('./routes/users'));
app.use('/api', require('./routes/passwordReset'));
app.use('/api', require('./routes/codeExec'));
app.use('/api', require('./routes/projects'));
app.get('/', (req, res) => {
  res.send('Server is running!');
});

// Socket.IO
const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    methods: ['GET','POST'],
    credentials: true
  },
  transports: ['websocket', 'polling']
});

// Collaboration socket logic
require('./socket/collaboration')(io);

// Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
