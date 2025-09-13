const express = require('express');
const router = express.Router();
const db = require('../db'); // adjust if needed

// Middleware to restrict access to admins
function checkAdmin(req, res, next) {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied' });
  }
  next();
}

// 🔹 Most active users (by project + file count)
router.get('/most-active-users', checkAdmin, (req, res) => {
  const query = `
    SELECT u.id, u.username, COUNT(DISTINCT p.id) AS projectCount, COUNT(f.id) AS fileCount
    FROM users u
    LEFT JOIN projects p ON u.id = p.user_id
    LEFT JOIN files f ON p.id = f.project_id
    GROUP BY u.id
    ORDER BY (projectCount + fileCount) DESC
    LIMIT 10;
  `;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    res.json(results);
  });
});

// 🔹 Project stats per user
router.get('/project-stats', checkAdmin, (req, res) => {
  const query = `
    SELECT users.username, COUNT(projects.id) AS totalProjects
    FROM users
    LEFT JOIN projects ON users.id = projects.user_id
    GROUP BY users.id;
  `;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    res.json(results);
  });
});

// 🔹 File stats per user
router.get('/file-stats', checkAdmin, (req, res) => {
  const query = `
    SELECT users.username, COUNT(files.id) AS totalFiles
    FROM users
    LEFT JOIN projects ON users.id = projects.user_id
    LEFT JOIN files ON projects.id = files.project_id
    GROUP BY users.id;
  `;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    res.json(results);
  });
});

// 🔹 Combined summary stats (used in dashboard summary card)
router.get('/summary', checkAdmin, (req, res) => {
  const summary = {
    totalUsers: 0,
    totalProjects: 0,
    totalFiles: 0
  };

  db.query('SELECT COUNT(*) AS total FROM users', (err, userResult) => {
    if (err) return res.status(500).json({ message: 'Failed to count users' });
    summary.totalUsers = userResult[0].total;

    db.query('SELECT COUNT(*) AS total FROM projects', (err, projResult) => {
      if (err) return res.status(500).json({ message: 'Failed to count projects' });
      summary.totalProjects = projResult[0].total;

      db.query('SELECT COUNT(*) AS total FROM files', (err, fileResult) => {
        if (err) return res.status(500).json({ message: 'Failed to count files' });
        summary.totalFiles = fileResult[0].total;

        res.json(summary);
      });
    });
  });
});

module.exports = router;
