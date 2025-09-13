const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const cors = require('cors');
const axios = require('axios');
const http = require('http');
const { Server } = require('socket.io');

dotenv.config();
const app = express();
const server = http.createServer(app);
const allowedOrigins = [
  'http://localhost:5173',
  'https://editor-haov.vercel.app'
];

const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      // allow requests with no origin (like Postman or server-to-server)
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error(`CORS not allowed for origin: ${origin}`));
      }
    },
    methods: ['GET', 'POST'],
    credentials: true
  }
});


app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cors({
  origin: [
    'http://localhost:5173',
    'https://editor-haov.vercel.app'
  ],
  credentials: true
}));


const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect(err => {
  if (err) throw err;
  console.log('✅ Connected to MySQL');
});

const sessionStore = new MySQLStore({}, db.promise());

app.use(session({
  key: 'workspace_session',
  secret: process.env.SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",   
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    maxAge: 24 * 60 * 60 * 1000
  }
}));


const adminRoutes = require('./routes/admin');
app.use('/api/admin', adminRoutes);



// ----------------- AUTH -----------------
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!email || !username || !password) {
    return res.status(400).json({ message: 'All fields required' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  
  // 🔁 Updated query to include default role = 'user'
  db.query(
    'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
    [username, email, hashedPassword, 'user'],
    (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: 'Email already registered' });
        }
        return res.status(500).json({ message: 'Server error' });
      }
      res.json({ message: 'Registered successfully' });
    }
  );
});


// app.post('/api/login', (req, res) => {
//   const { email, password } = req.body;
//   db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
//     if (err) return res.status(500).json({ message: 'DB error' });
//     if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

//     const user = results[0];
//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

//     req.session.user = { id: user.id, email: user.email };
//     res.json({ message: 'Login successful' });
//   });
// });

app.post('/api/login', (req, res) => {
  
  const { email, password } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ message: 'DB error' });
    if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    // ✅ Store role in session
    req.session.user = {
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role // 👈 this is the key addition
    };

    // ✅ Return user info with role to frontend
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



app.get('/api/check-auth', (req, res) => {
  if (req.session.user) {
    res.json({ authenticated: true, user: req.session.user });
  } else {
    res.status(401).json({ authenticated: false });
  }
});

app.get('/api/profile', (req, res) => {
  if (!req.session.user) return res.status(401).json({ message: 'Unauthorized' });

  const sql = 'SELECT id, username, email, created_at FROM users WHERE id = ?';
  db.query(sql, [req.session.user.id], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (results.length === 0) return res.status(404).json({ message: 'User not found' });
    res.json(results[0]);
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('workspace_session');
    res.json({ message: 'Logged out' });
  });
});

app.get('/api/users', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ message: 'Unauthorized' });
  }

  db.query('SELECT id, username, email, role FROM users', (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(results);
  });
});

app.post('/api/users/:id/role', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ message: 'Unauthorized' });
  }

  const userId = req.params.id;
  const { role } = req.body;

  if (!['user', 'admin'].includes(role)) {
    return res.status(400).json({ message: 'Invalid role' });
  }

  db.query('UPDATE users SET role = ? WHERE id = ?', [role, userId], (err) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json({ message: 'Role updated successfully' });
  });
});


const crypto = require('crypto');

app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ message: 'Token and password required' });

  db.query('SELECT * FROM password_resets WHERE token = ? AND expires_at > NOW()', [token], async (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (results.length === 0) return res.status(400).json({ message: 'Invalid or expired token' });

    const userId = results[0].user_id;
    const hashed = await bcrypt.hash(password, 10);

    db.query('UPDATE users SET password = ? WHERE id = ?', [hashed, userId], (err2) => {
      if (err2) return res.status(500).json({ message: 'Could not update password' });

      db.query('DELETE FROM password_resets WHERE user_id = ?', [userId]); // cleanup token
      res.json({ message: 'Password reset successful' });
    });
  });
});
const nodemailer = require('nodemailer');

app.post('/api/request-password-reset', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email is required' });

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, users) => {
    if (err) return res.status(500).json({ message: 'Database error' });

    // Always respond with a generic message to prevent account enumeration
    if (users.length === 0) {
      return res.json({ message: 'If the email is registered, a reset link has been sent.' });
    }

    const user = users[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000); // 1 hour

    db.query(
      'INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)',
      [user.id, token, expiresAt],
      (err2) => {
        if (err2) {
          console.error(err2);
          return res.status(500).json({ message: 'Could not save reset token' });
        }

        // Configure nodemailer
        const transporter = nodemailer.createTransport({
          service: 'gmail',
          auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
          }
        });

        const resetLink = `${process.env.BASE_CLIENT_URL}/reset-password/${token}`;
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: user.email,
          subject: '🔐 Workspace Password Reset',
          html: `
            <h3>Password Reset Requested</h3>
            <p>If you requested a password reset, click the link below:</p>
            <a href="${resetLink}" target="_blank">Reset Your Password</a>
            <p>This link will expire in 1 hour.</p>
            <br><small>If you didn’t request this, please ignore this email.</small>
          `
        };

        transporter.sendMail(mailOptions, (err3) => {
          if (err3) {
            console.error('Email send error:', err3);
            return res.status(500).json({ message: 'Failed to send reset email' });
          }

          res.json({ message: 'If the email is registered, a reset link has been sent.' });
        });
        console.log("📧 Preparing to send email to:", user.email);
console.log("📨 Reset link:", resetLink);

      }
    );
  });
});



app.post('/api/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  if (!newPassword) return res.status(400).json({ message: 'New password required' });

  db.query('SELECT * FROM password_resets WHERE token = ?', [token], async (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (results.length === 0) return res.status(400).json({ message: 'Invalid or expired token' });

    const reset = results[0];
    const now = new Date();
    if (new Date(reset.expires_at) < now) {
      return res.status(400).json({ message: 'Token has expired' });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    db.query('UPDATE users SET password = ? WHERE id = ?', [hashed, reset.user_id], (err) => {
      if (err) return res.status(500).json({ message: 'Failed to update password' });

      db.query('DELETE FROM password_resets WHERE user_id = ?', [reset.user_id]);
      res.json({ message: 'Password reset successful' });
    });
  });
});



// ----------------- CODE EXECUTION -----------------
app.post('/api/run-python', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Code is required' });

  try {
    const submissionRes = await axios.post(
      'https://judge0-ce.p.rapidapi.com/submissions?base64_encoded=false&wait=true',
      { source_code: code, language_id: 71 },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-RapidAPI-Key': process.env.RAPIDAPI_KEY,
          'X-RapidAPI-Host': 'judge0-ce.p.rapidapi.com'
        }
      }
    );

    const result = submissionRes.data;
    res.json({
      stdout: result.stdout,
      stderr: result.stderr,
      status: result.status,
      time: result.time,
      memory: result.memory
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Execution failed. Try again.' });
  }
});

app.post('/api/run-code', async (req, res) => {
  const { code, languageId } = req.body;

  if (!code || !languageId) {
    return res.status(400).json({ error: 'Code and languageId are required' });
  }

  try {
    const submissionRes = await axios.post(
      'https://judge0-ce.p.rapidapi.com/submissions?base64_encoded=false&wait=true',
      {
        source_code: code,
        language_id: languageId
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-RapidAPI-Key': process.env.RAPIDAPI_KEY,
          'X-RapidAPI-Host': 'judge0-ce.p.rapidapi.com'
        }
      }
    );

    const result = submissionRes.data;
    res.json({
      stdout: result.stdout,
      stderr: result.stderr,
      compile_output: result.compile_output,
      status: result.status.description,
      time: result.time,
      memory: result.memory
    });
  } catch (error) {
    console.error('Code execution error:', error.message);
    res.status(500).json({ error: 'Execution failed. Try again.' });
  }
});

// ----------------- PROJECT + FILE -----------------
app.post('/api/projects', (req, res) => {
  console.log('Session user:', req.session.user);
  const user = req.session.user;
  const { name } = req.body;
  if (!user) return res.status(401).json({ message: 'Unauthorized' });
  if (!name) return res.status(400).json({ message: 'Project name is required' });

  db.query('INSERT INTO projects (user_id, name) VALUES (?, ?)', [user.id, name], (err, result) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json({ message: 'Project created', projectId: result.insertId });
  });
});

app.get('/api/projects', (req, res) => {
  const user = req.session.user;
  if (!user) return res.status(401).json({ message: 'Unauthorized' });

  db.query('SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC', [user.id], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(results);
  });
});

app.post('/api/projects/:id/files', (req, res) => {
  const user = req.session.user;
  const { name, content } = req.body;
  const projectId = req.params.id;

  if (!user) return res.status(401).json({ message: 'Unauthorized' });
  if (!name) return res.status(400).json({ message: 'File name is required' });

  db.query(
    'INSERT INTO files (project_id, name, content) VALUES (?, ?, ?)',
    [projectId, name, content || ''],
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      res.json({ message: 'File created', fileId: result.insertId });
    }
  );
});

app.get('/api/projects/:id/files', (req, res) => {
  const user = req.session.user;
  const projectId = req.params.id;
  if (!user) return res.status(401).json({ message: 'Unauthorized' });

  db.query('SELECT * FROM files WHERE project_id = ? ORDER BY created_at ASC', [projectId], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(results);
  });
});

app.get('/api/files/:id', (req, res) => {
  const user = req.session.user;
  const fileId = req.params.id;
  if (!user) return res.status(401).json({ message: 'Unauthorized' });

  db.query('SELECT * FROM files WHERE id = ?', [fileId], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (results.length === 0) return res.status(404).json({ message: 'File not found' });
    res.json(results[0]);
  });
});

app.put('/api/files/:id', (req, res) => {
  const user = req.session.user;
  const fileId = req.params.id;
  const { content } = req.body;
  if (!user) return res.status(401).json({ message: 'Unauthorized' });

  db.query('UPDATE files SET content = ? WHERE id = ?', [content, fileId], (err) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json({ message: 'File updated' });
  });
});

app.delete('/api/files/:id', (req, res) => {
  const user = req.session.user;
  const fileId = req.params.id;
  if (!user) return res.status(401).json({ message: 'Unauthorized' });

  db.query('DELETE FROM files WHERE id = ?', [fileId], (err) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json({ message: 'File deleted' });
  });
});

app.delete('/api/projects/:id', (req, res) => {
  const user = req.session.user;
  const projectId = req.params.id;
  if (!user) return res.status(401).json({ message: 'Unauthorized' });

  db.query('DELETE FROM files WHERE project_id = ?', [projectId], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete files' });

    db.query('DELETE FROM projects WHERE id = ?', [projectId], (err2) => {
      if (err2) return res.status(500).json({ message: 'Failed to delete project' });
      res.json({ message: 'Project and its files deleted' });
    });
  });
});

// ----------------- SOCKET.IO COLLABORATION -----------------
const activeRooms = new Map();  // roomId => Set(socketIds)
const roomCodes = new Map();    // roomId => current code

io.on('connection', (socket) => {
  console.log('🧠 Socket connected:', socket.id);

  socket.on('createRoom', (roomId) => {
    if (!activeRooms.has(roomId)) {
      activeRooms.set(roomId, new Set());
      roomCodes.set(roomId, '');
    }
    socket.join(roomId);
    activeRooms.get(roomId).add(socket.id);
    socket.emit('roomCreated', roomId);
  });

  socket.on('joinRoom', (roomId) => {
    if (!activeRooms.has(roomId)) {
      socket.emit('joinError', '❌ Room does not exist');
      return;
    }
    socket.join(roomId);
    activeRooms.get(roomId).add(socket.id);
    const currentCode = roomCodes.get(roomId) || '';
    socket.emit('roomJoined', { roomId, currentCode });
  });

  socket.on('codeChange', ({ room, code }) => {
    roomCodes.set(room, code);
    socket.to(room).emit('codeUpdate', code);
  });

  socket.on('leaveRoom', (roomId) => {
    socket.leave(roomId);
    if (activeRooms.has(roomId)) {
      activeRooms.get(roomId).delete(socket.id);
      if (activeRooms.get(roomId).size === 0) {
        activeRooms.delete(roomId);
        roomCodes.delete(roomId);
      }
    }
  });

  // 💬 Chat message handler
  socket.on('chatMessage', ({ room, message, timestamp, id, sender }) => {
  socket.to(room).emit('newChatMessage', {
    message,
    timestamp,
    id,
    sender
  });
});



  socket.on('disconnect', () => {
    for (const [roomId, members] of activeRooms.entries()) {
      if (members.has(socket.id)) {
        members.delete(socket.id);
        if (members.size === 0) {
          activeRooms.delete(roomId);
          roomCodes.delete(roomId);
        }
      }
    }
  });
});


const PORT = process.env.PORT || 5000; // use Render's port if provided
const HOST = '0.0.0.0'; // bind to all interfaces so Render can detect it

server.listen(PORT, HOST, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
