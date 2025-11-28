e_nach_backend
==============

Project scaffold for e_nach_backend (CommonJS).

Instructions:
1. Copy .env and fill real secrets.
2. npm install
3. npm run dev (or npm start)
4. Project uses MySQL + Redis. Start those locally or update .env.

This scaffold includes basic auth flow (access + rotating refresh stored hashed in Redis),
RBAC middleware, sample routes, and NPCI external call placeholder.
