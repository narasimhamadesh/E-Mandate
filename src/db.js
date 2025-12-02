const mysql = require('mysql2/promise');
const config = require('./config/index');

const db = mysql.createPool({
  host: config.db.host,
  user: config.db.user,
  password: config.db.password,
  database: config.db.database,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test DB connection
(async () => {
  try {
    const connection = await db.getConnection();
    console.log("Connected to MySQL database (Promise Pool).");
    connection.release();
  } catch (err) {
    console.error("Database connection failed:", err);
  }
})();

module.exports = db;
