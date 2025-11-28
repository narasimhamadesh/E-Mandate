const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const redis = require('../redisClient');
const config = require('../config');
const { v4: uuidv4 } = require('uuid');

const ACCESS_EXP = config.jwt.accessExp;
const REFRESH_EXP = config.jwt.refreshExp;

function signAccessToken(payload) {
  return jwt.sign(payload, config.jwt.accessSecret, { expiresIn: ACCESS_EXP });
}

function signRefreshToken(payload) {
  return jwt.sign(payload, config.jwt.refreshSecret, { expiresIn: REFRESH_EXP });
}

async function saveRefreshToken(sessionId, refreshToken) {
  const hashed = await bcrypt.hash(refreshToken, 10);
  await redis.set(`refresh:${sessionId}`, hashed, 'EX', 60 * 60 * 24 * 30);
}

async function verifyRefreshToken(sessionId, token) {
  const storedHash = await redis.get(`refresh:${sessionId}`);
  if (!storedHash) return false;
  return bcrypt.compare(token, storedHash);
}

async function rotateRefreshToken(sessionId, oldToken) {
  const ok = await verifyRefreshToken(sessionId, oldToken);
  if (!ok) return null;
  const newToken = signRefreshToken({ sid: sessionId });
  await saveRefreshToken(sessionId, newToken);
  return newToken;
}

async function createSession(userId, ip, userAgent) {
  const sessionId = uuidv4();
  const meta = { userId, ip, userAgent, createdAt: Date.now() };
  await redis.set(`session:${sessionId}`, JSON.stringify(meta), 'EX', 60 * 60 * 24 * 30);
  return sessionId;
}

async function destroySession(sessionId) {
  await redis.del(`refresh:${sessionId}`);
  await redis.del(`session:${sessionId}`);
}

module.exports = {
  signAccessToken, signRefreshToken, saveRefreshToken,
  verifyRefreshToken, rotateRefreshToken, createSession, destroySession
};
