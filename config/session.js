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
    secure: process.env.NODE_ENV === 'production', // use true on Render (HTTPS)
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // allows cross-site cookies
    maxAge: 24 * 60 * 60 * 1000 // 1 day
  }
});
