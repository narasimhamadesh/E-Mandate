const { createLogger, transports, format } = require('winston');

const logger = createLogger({
  level: 'info',
  format: format.combine(format.timestamp(), format.json()),
  transports: [new transports.Console()]
});

// ----------------------------------
// Add logUserActivity function
// ----------------------------------
const logUserActivity = (userId, name, email, ip, action) => {
  logger.info({
    userId,
    name,
    email,
    ip,
    action,
    timestamp: new Date()
  });
};

// Export both
module.exports = {
  logger,
  logUserActivity
};
