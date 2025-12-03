// const Redis = require('ioredis');
// const config = require('./config');
// const redis = new Redis({
//   host: config.redis.host,
//   port: config.redis.port,
//   password: config.redis.password || undefined,
// });
// redis.on('error', (err) => console.error('Redis error', err));
// module.exports = redis;


const Redis = require('ioredis');
const config = require('./config');

const redis = new Redis({
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password || undefined,
});

// 🔥 Log when Redis connects successfully
redis.on('connect', () => {
  console.log('✅ Redis connected:', config.redis.host + ':' + config.redis.port);
});

// 🔥 Log when Redis is ready (fully initialized)
redis.on('ready', () => {
  console.log('🚀 Redis is ready to use');
});

// Log if Redis fails
redis.on('error', (err) => {
  console.error('Redis error:', err);
});

// ⚠️ Log when Redis disconnects
redis.on('close', () => {
  console.log('⚠️ Redis connection closed');
});

module.exports = redis;
