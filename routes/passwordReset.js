const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const db = require('../config/db');
const { createTransport } = require('nodemailer');
const mailer = require('../utils/mailer');
const router = express.Router();

// Request password reset
router.post('/request-password-reset', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email is required' });

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, users) => {
    if (err) return res.status(500).json({ message: 'Database error' });

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

        const transporter = mailer.getTransport();
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

// Reset password (token in body)
router.post('/reset-password', async (req, res) => {
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

// Reset password (token in URL)
router.post('/reset-password/:token', async (req, res) => {
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

module.exports = router;