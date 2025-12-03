const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const axios = require('axios');
const os = require('os');
const requestIp = require('request-ip');
const nodemailer = require('nodemailer');
const { validatePassword } = require("../utils/passwordPolicy");

const db = require('../db');
const config = require('../config');

const { sendEmail } = require("../services/email.service");
const { generatePassword } = require("../utils/passwordPolicy");
const { logUserActivity } = require("./userlog.controller");


exports.getUsers = async (req, res) => {
  try {
    const authenticatedUser = req.user;
    console.log("Authenticated User:", authenticatedUser);

    // Only Admins can access user list
    if (authenticatedUser.role !== 1) {
      return res.status(403).json({ message: "Access denied. Admin only." });
    }

    // Fetch users (Admins only)
    const [users] = await db.query(
      "SELECT name, email, userId, company, phoneNumber, role_id FROM users WHERE role_id = 1"
    );

    return res.json({
      authenticatedUser,
      users
    });

  } catch (err) {
    console.error("Error fetching users:", err);
    return res.status(500).json({
      message: "Server Error",
      error: err.message
    });
  }
};



// Promisified DB query helper
const query = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.query(sql, params, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });

exports.createUser = async (req, res) => {
  const { userId, name, email, company, phoneNumber, role } = req.body;
  const ipAddress = req.ip;

  if (!userId || !name || !email || !company || !phoneNumber || !role) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    // 1. Lookup role
    const normalizedRole = role.trim().replace(/\s+/g, "_").toLowerCase();
    const roles = await query(
      "SELECT id FROM roles WHERE LOWER(role_name) = ?",
      [normalizedRole]
    );

    if (roles.length === 0)
      return res.status(400).json({ message: "Invalid role" });

    const role_id = roles[0].id;

    // 2. Generate password
    const plainPassword = generatePassword();
    const hashed = await bcrypt.hash(plainPassword, 10);

    // 3. Insert user
    await query(
      `INSERT INTO users (userId, name, email, role_id, company, phoneNumber, password)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [userId, name, email, role_id, company, phoneNumber, hashed]
    );

    // 4. Send email using centralized email service
    await sendEmail({
      to: email,
      subject: "Your Account Credentials",
      text: `
Hello ${name},

Your account has been created successfully.

Login ID : ${userId}
Password : ${plainPassword}

Please change your password after logging in.
      `,
    });

    // 5. Log activity
    logUserActivity(userId, name, email, ipAddress, "User created by admin");

    return res.json({
      message: "User created successfully & email sent",
      user: { userId, name, email, role_id, company, phoneNumber },
    });
  } catch (err) {
    console.error("Error creating user:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
};



exports.updatePassword = async (req, res) => {
  const userId = req.user.id; // authenticated user id
  const { oldPassword, newPassword } = req.body;

  console.log("Update password request:", req.body);

  // Validate request
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ message: "Old and new passwords are required" });
  }

  // if (!validatePassword(newPassword)) {
  //   return res.status(400).json({ message: "Weak password format" });
  // }

  try {
    // 1. Fetch user from DB
    const [rows] = await db.query(
      "SELECT id, password FROM users WHERE id = ? LIMIT 1",
      [userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = rows[0];

    // 2. Check old password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Old password is incorrect" });
    }

    // 3. Hash new password
    const hashed = await bcrypt.hash(newPassword, 10);

    // 4. Set new password expiry (optional: 45 days)
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 45);

    // 5. Update password
    await db.query(
      `UPDATE users 
       SET password = ?, password_expiry_date = ?, reset_token = NULL, reset_token_expiry = NULL 
       WHERE id = ?`,
      [hashed, expiryDate, userId]
    );

    return res.json({ message: "Password updated successfully" });

  } catch (error) {
    console.error("Update password error:", error);
    return res.status(500).json({ message: "Server error", error: error.message });
  }
};
