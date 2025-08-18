const express = require('express');
const db = require('../config/db');
const router = express.Router();

// Create project
router.post('/projects', (req, res) => {
  const user = req.session.user;
  const { name } = req.body;
  if (!user) return res.status(401).json({ message: 'Unauthorized' });
  if (!name) return res.status(400).json({ message: 'Project name is required' });

  db.query('INSERT INTO projects (user_id, name) VALUES (?, ?)', [user.id, name], (err, result) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json({ message: 'Project created', projectId: result.insertId });
  });
});

// Get projects for current user
router.get('/projects', (req, res) => {
  const user = req.session.user;
  if (!user) return res.status(401).json({ message: 'Unauthorized' });

  db.query('SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC', [user.id], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(results);
  });
});

// Create file in project
router.post('/projects/:id/files', (req, res) => {
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

// List files in project
router.get('/projects/:id/files', (req, res) => {
  const user = req.session.user;
  const projectId = req.params.id;
  if (!user) return res.status(401).json({ message: 'Unauthorized' });

  db.query('SELECT * FROM files WHERE project_id = ? ORDER BY created_at ASC', [projectId], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(results);
  });
});

// Get single file
router.get('/files/:id', (req, res) => {
  const user = req.session.user;
  const fileId = req.params.id;
  if (!user) return res.status(401).json({ message: 'Unauthorized' });

  db.query('SELECT * FROM files WHERE id = ?', [fileId], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (results.length === 0) return res.status(404).json({ message: 'File not found' });
    res.json(results[0]);
  });
});

// Update file
router.put('/files/:id', (req, res) => {
  const user = req.session.user;
  const fileId = req.params.id;
  const { content } = req.body;
  if (!user) return res.status(401).json({ message: 'Unauthorized' });

  db.query('UPDATE files SET content = ? WHERE id = ?', [content, fileId], (err) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json({ message: 'File updated' });
  });
});

// Delete file
router.delete('/files/:id', (req, res) => {
  const user = req.session.user;
  const fileId = req.params.id;
  if (!user) return res.status(401).json({ message: 'Unauthorized' });

  db.query('DELETE FROM files WHERE id = ?', [fileId], (err) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json({ message: 'File deleted' });
  });
});

// Delete project (and its files)
router.delete('/projects/:id', (req, res) => {
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

module.exports = router;