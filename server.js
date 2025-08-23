const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const db = require('./config/db'); // your MySQL connection

dotenv.config();
const app = express();
app.use(express.json());
const server = http.createServer(app);

// Allowed origins
const allowedOrigins = [
  'http://localhost:5173',          
  'https://editior.vercel.app',
  'https://editor-haov.vercel.app/'      
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
app.use(require('./config/session'));

// Routes
app.use('/api/admin', require('./routes/admin'));
app.use('/api', require('./routes/auth'));
app.use('/api', require('./routes/users'));
app.use('/api', require('./routes/passwordReset'));
app.use('/api', require('./routes/codeExec'));
app.use('/api', require('./routes/projects'));

// Root route
app.get('/', (req, res) => {
  res.send('Server is running!');
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ message: 'DB error' });
    if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    req.session.user = {
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role
    };

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role
      }
    });
  });
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
