const Redis = require('ioredis');
const config = require('./config');
const redis = new Redis({
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password || undefined,
});
redis.on('error', (err) => console.error('Redis error', err));
module.exports = redis;
