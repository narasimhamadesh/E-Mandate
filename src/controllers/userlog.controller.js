const db = require("../db");

// Function to log user activity
const logUserActivity = (userId, name, email, ipAddress, activity) => {
  const date = new Date();
  const query = `
    INSERT INTO user_logs (user_id, name, email, ip_address, activity, date)
    VALUES (?, ?, ?, ?, ?, ?)
  `;
  db.query(query, [userId, name, email, ipAddress, activity, date], (err) => {
    if (err) {
      console.error("Error logging user activity:", err);
    }
  });
};

// Controller to get all user logs
const getUserLogs = (req, res) => {
  db.query("SELECT * FROM user_logs ORDER BY date DESC", (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Database error", error: err });
    }
    res.json(results);
  });
};

module.exports = { logUserActivity, getUserLogs };
