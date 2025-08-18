const express = require('express');
const router = express.Router();

// Placeholder admin routes file.
// Your original project already required './routes/admin' in index.js.
// Keep this file as a module so requiring it doesn't break your app.
// Add or replace admin routes here if you want later.

router.get('/', (req, res) => {
  res.json({ message: 'Admin root (placeholder)' });
});

module.exports = router;