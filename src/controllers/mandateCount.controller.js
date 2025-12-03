const db = require("../db");

exports.getMandatesByDateRange = (req, res) => {
  const { range } = req.params;

  let sql = "";
  if (range === "daily") {
    sql = `SELECT COUNT(*) AS count FROM e_mandates WHERE DATE(created_at) = CURDATE() AND frequency = 'daily'`;
  } 
  else if (range === "weekly") {
    sql = `SELECT COUNT(*) AS count FROM e_mandates 
           WHERE YEARWEEK(created_at, 1) = YEARWEEK(CURDATE(), 1) 
           AND frequency = 'weekly'`;
  }
  else if (range === "monthly") {
    sql = `SELECT MONTH(created_at) AS month, COUNT(*) AS count 
           FROM e_mandates 
           WHERE YEAR(created_at) = YEAR(CURDATE()) 
           AND frequency = 'monthly'
           GROUP BY MONTH(created_at)`;
  }
  else if (range === "yearly") {
    sql = `SELECT COUNT(*) AS count 
           FROM e_mandates 
           WHERE YEAR(created_at) = YEAR(CURDATE()) 
           AND frequency = 'yearly'`;
  }
  else {
    return res.status(400).json({ error: "Invalid Range" });
  }

  db.query(sql, (err, result) => {
    if (err) {
      console.error("Error fetching mandates:", err);
      return res.status(500).json({ error: "Failed to fetch mandates" });
    }
    res.json(result);
  });
};
