const db = require("../db");

// ======================================
// LOG USER ACTIVITY  (ASYNC VERSION)
// ======================================
const logUserActivity = async (userId, name, email, ipAddress, activity) => {
  try {
    const date = new Date();

    await db.query(
      `
      INSERT INTO user_logs (user_id, name, email, ip_address, activity, date)
      VALUES (?, ?, ?, ?, ?, ?)
      `,
      [userId, name, email, ipAddress, activity, date]
    );

  } catch (err) {
    console.error("Error logging user activity:", err);
  }
};

// ======================================
// GET ALL LOGS (ASYNC VERSION)
// ======================================
const getUserLogs = async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT * FROM user_logs ORDER BY date DESC"
    );

    return res.json(rows);

  } catch (err) {
    return res
      .status(500)
      .json({ message: "Database error", error: err.message });
  }
};

module.exports = { logUserActivity, getUserLogs };
