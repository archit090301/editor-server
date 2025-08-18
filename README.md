# Workspace Backend (Modularized)
This is a modularized version of your backend. All original routes and endpoints are preserved exactly
so the frontend should continue to work without changes.

## How to use
1. Copy `.env.example` to `.env` and fill in values.
2. `npm install`
3. `npm run dev` or `npm start`

## Structure
- server.js - entrypoint
- config/ - db and session
- routes/ - split route handlers
- socket/ - collaboration (socket.io)
- utils/ - mail helper

The API paths (example): `/api/register`, `/api/login`, `/api/projects`, `/api/files/:id`, etc.