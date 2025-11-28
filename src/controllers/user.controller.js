const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const axios = require('axios');
const os = require('os');
const requestIp = require('request-ip');
const nodemailer = require('nodemailer');

const db = require('../db');
const config = require('../config');




exports.getUsers = (req, res) => {
    const authenticatedUser = req.user; 
    console.log("Authenticated User:", authenticatedUser);
  
    // Example authorization rule: only admin (role_id = 1) can access users list
    if (authenticatedUser.role !== 1) {
      return res.status(403).json({ message: "Access denied. Admin only." });
    }
  
    db.query(
      "SELECT name, email, userId, company, phoneNumber, role_id FROM users WHERE role_id = 1",
      (err, results) => {
        if (err) {
          console.error("Error fetching users:", err);
          return res.status(500).json({ message: "Server Error", error: err.message });
        }
  
        return res.json({
          authenticatedUser,
          users: results
        });
      }
    );
  };
  