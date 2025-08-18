const express = require('express');
const axios = require('axios');
const db = require('../config/db');
const router = express.Router();

router.post('/run-python', async (req, res) => {
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

router.post('/run-code', async (req, res) => {
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

module.exports = router;