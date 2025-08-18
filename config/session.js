const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const db = require('./db');
const dotenv = require('dotenv');
dotenv.config();

const sessionStore = new MySQLStore({}, db.promise());

module.exports = session({
  key: 'workspace_session',
  secret: process.env.SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
});