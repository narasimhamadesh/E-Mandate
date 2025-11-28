// -----------------------------------------------
// IMPORTS
// -----------------------------------------------
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const axios = require('axios');
const os = require('os');
const requestIp = require('request-ip');
const nodemailer = require('nodemailer');

const db = require('../db');
const config = require('../config');


const { validatePassword } = require('../utils/passwordPolicy');

// Redis-based auth services
const { 
  createSession,
  rotateRefreshToken,
  destroySession,
  saveRefreshToken,
  signAccessToken, signRefreshToken
} = require('../services/auth.service');

// const { signAccessToken, signRefreshToken } = require('../utils/jwt');
const { logUserActivity } = require('../utils/logger');

// Get real IP address
const getIpAddress = (req) => {
  const clientIp = requestIp.getClientIp(req);

  if (clientIp === '::1' || clientIp === '127.0.0.1') {
    const networkInterfaces = os.networkInterfaces();
    for (const key in networkInterfaces) {
      for (const address of networkInterfaces[key]) {
        if (address.family === 'IPv4' && !address.internal) {
          return address.address;
        }
      }
    }
  }
  return clientIp;
};


const verifyCaptcha = async (captchaToken) => {
  try {
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;
    const response = await axios.post(
      "https://www.google.com/recaptcha/api/siteverify",
      null,
      {
        params: {
          secret: secretKey,
          response: captchaToken,
        },
      }
    );
    console.log("reCAPTCHA response:", response.data);
    return response.data.success;
  } catch (error) {
    console.error("reCAPTCHA verification error:", error.message);
    return false;
  }
};

// Nodemailer transporter (same as old)
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

// Send password expiry warning email
const sendPasswordExpiryNotification = (user, daysRemaining) => {
  transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: 'Password Expiry Warning',
    text: `Your password will expire in ${daysRemaining} day(s). Please update it.`,
  });
};





exports.login = async (req, res) => {
  const { userId, password, captchaToken } = req.body;
  const ipAddress = getIpAddress(req);       

  console.log("Login request body:", req.body);
  
  console.log("Received login request:", { userId, ipAddress });

  console.log("Login attempt for userId:", userId, "from IP:", ipAddress);

  if (!captchaToken) {
    console.log("Captcha token missing");
    return res.status(400).json({ message: "Captcha is required" });
  }

  const isValidCaptcha = await verifyCaptcha(captchaToken);
  if (!isValidCaptcha) {
    console.log("Invalid CAPTCHA");
    return res.status(400).json({ message: "Invalid CAPTCHA" });
  }

  console.log("Step 1: Before DB query");

  db.query("SELECT 1", (err, rs) => {
    console.log("DB test error:", err);
    console.log("DB test result:", rs);
  });
  
  try {
    db.query(
      `
        SELECT 
          users.*, 
          roles.role_name AS role 
        FROM users
        JOIN roles ON users.role_id = roles.id
        WHERE users.userId = ?
      `,
      [userId],
      async (err, results) => {
        if (err) return res.status(500).json({ message: "Database error" });

        if (results.length === 0) {
          return res.status(400).json({ message: "User does not exist" });
        }

        console.log("Step 2: Inside DB callback");

        const user = results[0];

        // --------------------------
        // Check password expiry
        // --------------------------
        const expiryDate = new Date(user.password_expiry_date);
        const daysRemaining = Math.ceil(
          (expiryDate - new Date()) / (1000 * 60 * 60 * 24)
        );

        if (daysRemaining <= 0) {
          return res.status(401).json({
            message: "Password expired. Please reset your password.",
          });
        }

        // --------------------------
        // Compare Password
        // --------------------------

        console.log("Step 3: After finding user");
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          logUserActivity(
            user.id,
            user.name,
            user.email,
            ipAddress,
            "Incorrect password attempt"
          );
          return res.status(400).json({ message: "Incorrect password" });
        }

        // --------------------------
        // Log successful login
        // --------------------------
        logUserActivity(
          user.id,
          user.name,
          user.email,
          ipAddress,
          "User logged in"
        );

        // --------------------------
        // WARNING + Email Notification
        // --------------------------
        let warningMsg = null;

        if (daysRemaining <= 3) {
          warningMsg = `Password expires in ${daysRemaining} day(s)`;

          // Send only once per day
          if (
            !user.last_expiry_notification_date ||
            new Date(user.last_expiry_notification_date).toDateString() !==
              new Date().toDateString()
          ) {
            sendPasswordExpiryNotification(user, daysRemaining);

            db.query(
              "UPDATE users SET last_expiry_notification_date = NOW() WHERE id = ?",
              [user.id]
            );
          }
        }

        // ======================================================
        //              REDIS SESSION CREATION
        // ======================================================

        console.log("Step 4: After bcrypt compare");
        const sessionId = await createSession(
          user.id,
          ipAddress,
          req.get("User-Agent")
        );

        // --------------------------
        // JWT Access Token
        // --------------------------

        console.log("Step 5: After createSession");
        const token = signAccessToken({
          sub: user.id,
          role: user.role_id,
          sid: sessionId,
        });

        // --------------------------
        // JWT Refresh Token
        // --------------------------

        console.log("Step 6: After signing refresh token");
        const refreshToken = signRefreshToken({
          sub: user.id,
          sid: sessionId,
        });

        await saveRefreshToken(sessionId, refreshToken);

        // --------------------------
        // Set Cookie
        // --------------------------
        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: config.cookie.secure,
          sameSite: config.cookie.sameSite,
          domain: config.cookie.domain,
          path: "/api/auth",
          maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
        });

        // ======================================================
        //               FINAL RESPONSE
        // ======================================================
        console.log("Step 7: After saveRefreshToken");
        res.json({
          
          token,
          expiresIn: config.jwt.accessExp,
          warning: warningMsg,
          user: {
            id: user.id,
            name: user.name,
            userid: user.userId,
            email: user.email,
            role: user.role,
            role_id: user.role_id,
          },
        });
        console.log("Step 8: After sending response");
      }
    );
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
};


// -----------------------------------------------
// REFRESH TOKEN
// -----------------------------------------------
exports.refresh = async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ message: 'No token' });

  try {
    const payload = jwt.verify(token, config.jwt.refreshSecret);
    const sessionId = payload.sid;

    const newRefresh = await rotateRefreshToken(sessionId, token);
    if (!newRefresh) {
      await destroySession(sessionId);
      return res.status(401).json({ message: 'Invalid session' });
    }

    const accessToken = signAccessToken({
      sub: payload.sub,
      role: payload.role,
      sid: sessionId,
    });

    res.cookie('refreshToken', newRefresh, {
      httpOnly: true,
      secure: config.cookie.secure,
      sameSite: config.cookie.sameSite,
      domain: config.cookie.domain,
      path: '/api/auth',
      maxAge: 1000 * 60 * 60 * 24 * 30,
    });

    return res.json({ accessToken });
  } catch (err) {
    res.clearCookie('refreshToken', { path: '/api/auth' });
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// -----------------------------------------------
// LOGOUT
// -----------------------------------------------
exports.logout = async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(204).end();

  try {
    const payload = jwt.verify(token, config.jwt.refreshSecret);
    const sessionId = payload.sid;

    await destroySession(sessionId);
    res.clearCookie('refreshToken', { path: '/api/auth' });
    return res.status(200).json({ message: 'Logged out' });
  } catch (err) {
    res.clearCookie('refreshToken', { path: '/api/auth' });
    return res.status(200).json({ message: 'Logged out' });
  }
};

// -----------------------------------------------
// FORGOT PASSWORD (unchanged except IP logging)
// -----------------------------------------------
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;
  const ip = getIpAddress(req);

  if (!email) return res.status(400).json({ message: 'Email required' });

  try {
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (!rows.length) return res.status(400).json({ message: 'User not found' });

    const user = rows[0];

    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashed = await bcrypt.hash(resetToken, 10);
    const expiry = new Date(Date.now() + 3600000);

    await db.query(
      'UPDATE users SET reset_token=?, reset_token_expiry=? WHERE id=?',
      [hashed, expiry, user.id]
    );

    logUserActivity(user.id, user.name, user.email, ip, 'Requested password reset');

    const url = `http://localhost:3000/reset-password/${resetToken}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset',
      text: `Click the link to reset password\n${url}\nValid for 1 hour.`,
    });

    return res.json({ message: 'Reset link sent to email' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
};


exports.sendPasswordExpiryNotification = async (user, daysRemaining) => {
  const resetLink = `${process.env.FRONTEND_URL}/reset-expired-password`;

  const subject = `Password Expiry Notice (${daysRemaining} day${daysRemaining > 1 ? "s" : ""} remaining)`;

  const message = `
      Dear ${user.name},<br><br>
      Your password will expire in <strong>${daysRemaining} day${daysRemaining > 1 ? "s" : ""}</strong>.<br>
      Expiry Date: <strong>${user.password_expiry_date}</strong><br><br>
      Please update your password to avoid account lockout.<br><br>
      <a href="${resetLink}" style="padding:10px 20px;background:#007bff;color:white;text-decoration:none;border-radius:5px;">
        Reset Password
      </a>
      <br><br>Regards,<br>Security Team
  `;

  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to: user.email,
    subject,
    html: message,
  });
};


exports.sendExpiredPasswordResetLink = async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ message: "Email is required" });

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, users) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (users.length === 0) return res.status(404).json({ message: "User not found" });

    const user = users[0];

    const resetToken = crypto.randomBytes(40).toString("hex");
    const hashedToken = await bcrypt.hash(resetToken, 10);
    const expiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    db.query(
      "UPDATE users SET reset_token=?, reset_token_expiry=? WHERE id=?",
      [hashedToken, expiry, user.id],
      async (err) => {
        if (err) return res.status(500).json({ message: "DB update error" });

        const link = `${process.env.FRONTEND_URL}/reset-expired-password/${resetToken}`;

        await transporter.sendMail({
          to: email,
          from: process.env.EMAIL_FROM,
          subject: "Reset Expired Password",
          html: `
              You requested a password reset.<br><br>
              <a href="${link}">Click here</a> to reset your password.<br><br>
              This link expires in <strong>1 hour</strong>.
          `,
        });

        return res.json({ message: "Reset link sent successfully" });
      }
    );
  });
};


exports.resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword)
    return res.status(400).json({ message: "Token and new password are required" });

  if (!validatePassword(newPassword))
    return res.status(400).json({ message: "Weak password format" });

  db.query(
    "SELECT * FROM users WHERE reset_token IS NOT NULL AND reset_token_expiry > NOW()",
    async (err, users) => {
      if (err) return res.status(500).json({ message: "Database error" });

      // Validate by comparing hashed token
      const user = users.find((u) => bcrypt.compareSync(token, u.reset_token));

      if (!user) return res.status(400).json({ message: "Invalid or expired token" });

      const hashed = await bcrypt.hash(newPassword, 10);

      db.query(
        "UPDATE users SET password=?, reset_token=NULL, reset_token_expiry=NULL WHERE id=?",
        [hashed, user.id],
        (err) => {
          if (err) return res.status(500).json({ message: "Error updating password" });

          return res.json({ message: "Password updated successfully" });
        }
      );
    }
  );
};



exports.resetExpiredPassword = async (req, res) => {
  const { token, oldPassword, newPassword, confirmPassword } = req.body;

  if (!token || !oldPassword || !newPassword || !confirmPassword)
    return res.status(400).json({ message: "All fields are required" });

  if (!validatePassword(newPassword))
    return res.status(400).json({ message: "Weak password" });

  if (newPassword !== confirmPassword)
    return res.status(400).json({ message: "Passwords do not match" });

  if (newPassword === oldPassword)
    return res.status(400).json({ message: "New password cannot be same as old" });

  db.query(
    "SELECT * FROM users WHERE reset_token IS NOT NULL AND reset_token_expiry > NOW()",
    async (err, users) => {
      if (err) return res.status(500).json({ message: "Database error" });

      const user = users.find((u) => bcrypt.compareSync(token, u.reset_token));
      if (!user) return res.status(400).json({ message: "Invalid or expired token" });

      const isOldCorrect = await bcrypt.compare(oldPassword, user.password);
      if (!isOldCorrect)
        return res.status(400).json({ message: "Incorrect old password" });

      const hashed = await bcrypt.hash(newPassword, 10);
      const expiry = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);

      db.query(
        "UPDATE users SET password=?, reset_token=NULL, reset_token_expiry=NULL, password_created_at=NOW(), password_expiry_date=? WHERE id=?",
        [hashed, expiry, user.id],
        (err) => {
          if (err) return res.status(500).json({ message: "Password update error" });

          return res.json({ message: "Password reset successful" });
        }
      );
    }
  );
};




