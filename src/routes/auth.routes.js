const express = require('express');
const router = express.Router();
const authMiddleware= require('../middleware/auth.middleware');
const { login, refresh, logout ,getUsers} = require('../controllers/auth.controller');
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  handler: (req, res) => res.status(429).json({ message: 'Too many login attempts, try later' })
});

router.post('/login', loginLimiter, login);
router.post('/refresh', refresh);
router.post('/logout', logout); 

module.exports = router;
