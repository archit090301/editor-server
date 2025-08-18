const express = require('express');
const db = require('../config/db');
const router = express.Router();

// Get all users (admin only)
router.get('/users', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ message: 'Unauthorized' });
  }

  db.query('SELECT id, username, email, role FROM users', (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(results);
  });
});

// Update role (admin only)
router.post('/users/:id/role', (req, res) => {
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

module.exports = router;