// -----------------------------------------------
// IMPORTS
// -----------------------------------------------
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const axios = require('axios');
const os = require('os');
const requestIp = require('request-ip');
// const nodemailer = require('nodemailer');

const { sendEmail } = require("../services/email.service");

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

// // Nodemailer transporter (same as old)
// const transporter = nodemailer.createTransport({
//   service: 'Gmail',
//   auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
// });

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

  if (!captchaToken) {
    return res.status(400).json({ message: "Captcha is required" });
  }

  const isValidCaptcha = await verifyCaptcha(captchaToken);
  if (!isValidCaptcha) {
    return res.status(400).json({ message: "Invalid CAPTCHA" });
  }

  try {
    console.log("Step 1: Before DB query");

    // 🔥 FIXED: REMOVE CALLBACK. Use await.
    const [results] = await db.query(
      `
        SELECT 
          users.*, 
          roles.role_name AS role 
        FROM users
        JOIN roles ON users.role_id = roles.id
        WHERE users.userId = ?
      `,
      [userId]
    );

    if (results.length === 0) {
      return res.status(400).json({ message: "User does not exist" });
    }

    console.log("Step 2: User found");

    const user = results[0];

    // --------------------------
    // Password Expiry Check
    // --------------------------
    const expiryDate = new Date(user.password_expiry_date);
    const daysRemaining = Math.ceil((expiryDate - new Date()) / (1000 * 60 * 60 * 24));

    if (daysRemaining <= 0) {
      return res.status(401).json({
        message: "Password expired. Please reset your password.",
      });
    }

    // --------------------------
    // Password Compare
    // --------------------------
    console.log("Step 3: Checking password");

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

    // Log login
    logUserActivity(user.id, user.name, user.email, ipAddress, "User logged in");

    // --------------------------
    // Warning Notification
    // --------------------------
    let warningMsg = null;

    if (daysRemaining <= 3) {
      warningMsg = `Password expires in ${daysRemaining} day(s)`;

      if (
        !user.last_expiry_notification_date ||
        new Date(user.last_expiry_notification_date).toDateString() !==
          new Date().toDateString()
      ) {
        sendPasswordExpiryNotification(user, daysRemaining);

        // 🔥 FIXED: Use await
        await db.query(
          "UPDATE users SET last_expiry_notification_date = NOW() WHERE id = ?",
          [user.id]
        );
      }
    }

    // ======================================================
    //                   REDIS SESSION
    // ======================================================
    console.log("Step 4: Creating session");

    const sessionId = await createSession(
      user.id,
      ipAddress,
      req.get("User-Agent")
    );

    // --------------------------
    // JWT Tokens
    // --------------------------
    const token = signAccessToken({
      sub: user.id,
      role: user.role_id,
      sid: sessionId,
    });

    const refreshToken = signRefreshToken({
      sub: user.id,
      sid: sessionId,
    });

    await saveRefreshToken(sessionId, refreshToken);

    // --------------------------
    // Cookie
    // --------------------------
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: config.cookie.secure,
      sameSite: config.cookie.sameSite,
      domain: config.cookie.domain,
      path: "/api/auth",
      maxAge: 1000 * 60 * 60 * 24 * 30,
    });

    // ======================================================
    //                   FINAL RESPONSE
    // ======================================================
    console.log("Step 5: Sending response");

    return res.json({
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

  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};



// -----------------------------------------------
// REFRESH TOKEN
// -----------------------------------------------
exports.refresh = async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const payload = jwt.verify(token, config.jwt.refreshSecret);
    const sessionId = payload.sid;

    const newRefresh = await rotateRefreshToken(sessionId, token);
    if (!newRefresh) {
      await destroySession(sessionId);
      return res.status(401).json({ message: "Invalid session" });
    }

    const accessToken = signAccessToken({
      sub: payload.sub,
      role: payload.role,
      sid: sessionId,
    });

    // res.cookie("refreshToken", newRefresh, {
    //   httpOnly: true,
    //   secure: config.cookie.secure,
    //   sameSite: config.cookie.sameSite,
    //   domain: config.cookie.domain,
    //   path: "/api/auth",
    //   maxAge: 1000 * 60 * 60 * 24 * 30,
    // });

    const cookieOptions = {
      httpOnly: true,
      secure: config.cookie.secure,            // false in dev, true in prod
      sameSite: config.cookie.sameSite,        // Lax in dev, None in prod
      domain: config.cookie.domain || undefined,  // undefined in dev
      path: "/",
      maxAge: 1000 * 60 * 60 * 24 * 30,
    };
    
    res.cookie("refreshToken", newRefresh, cookieOptions);
    
    // ------------------- IN PRODUCTION ------------------------

    // res.cookie("refreshToken", newRefresh, {
    //   httpOnly: true,
    //   secure: true,          // only on HTTPS
    //   sameSite: "None",      // required for secure cookies
    //   domain: "yourdomain.com",
    //   path: "/",
    //   maxAge: 1000 * 60 * 60 * 24 * 30,
    // });
    
    

    return res.json({ accessToken });
  } catch (err) {
    res.clearCookie("refreshToken", { path: "/api/auth" });
    return res.status(401).json({ message: "Invalid token" });
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

    res.clearCookie("refreshToken", { path: "/api/auth" });
    return res.json({ message: "Logged out" });
  } catch (err) {
    res.clearCookie("refreshToken", { path: "/api/auth" });
    return res.json({ message: "Logged out" });
  }
};


// -----------------------------------------------
// FORGOT PASSWORD (unchanged except IP logging)
// -----------------------------------------------
// exports.forgotPassword = async (req, res) => {
//   const { email } = req.body;
//   const ip = getIpAddress(req);

//   if (!email) {
//     return res.status(400).json({ message: 'Email required' });
//   }

//   try {
//     // 1. Check user exists
//     const [rows] = await db.query(
//       'SELECT id, name, email FROM users WHERE email = ? LIMIT 1',
//       [email]
//     );

//     if (rows.length === 0) {
//       return res.status(400).json({ message: 'User not found' });
//     }

//     const user = rows[0];

//     // 2. Generate reset token
//     const resetToken = crypto.randomBytes(32).toString('hex');
//     const hashed = await bcrypt.hash(resetToken, 10);
//     const expiry = new Date(Date.now() + 3600000); // 1 hour

//     // 3. Save token & expiry
//     await db.query(
//       `UPDATE users 
//        SET reset_token = ?, reset_token_expiry = ?
//        WHERE id = ?`,
//       [hashed, expiry, user.id]
//     );

//     // 4. Log activity
//     logUserActivity(
//       user.id,
//       user.name,
//       user.email,
//       ip,
//       'Requested password reset'
//     );

//     // 5. Reset URL
//     const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

//     // 6. Send email
//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: email,
//       subject: 'Password Reset',
//       text: `Click the link below to reset your password:\n${resetUrl}\n\nThis link is valid for 1 hour.`,
//     });

//     return res.json({ message: 'Reset link sent to email' });

//   } catch (err) {
//     console.error('Forgot Password Error:', err);
//     return res.status(500).json({ message: 'Server error' });
//   }
// };

   // <-- import email service

exports.forgotPassword = async (req, res) => {
  const { email } = req.body;
  const ip = getIpAddress(req);

  if (!email) {
    return res.status(400).json({ message: 'Email required' });
  }

  try {
    // 1. Check user exists
    const [rows] = await db.query(
      'SELECT id, name, email FROM users WHERE email = ? LIMIT 1',
      [email]
    );

    if (rows.length === 0) {
      return res.status(400).json({ message: 'User not found' });
    }

    const user = rows[0];

    // 2. Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashed = await bcrypt.hash(resetToken, 10);
    const expiry = new Date(Date.now() + 3600000);

    // 3. Save token
    await db.query(
      `UPDATE users 
       SET reset_token = ?, reset_token_expiry = ?
       WHERE id = ?`,
      [hashed, expiry, user.id]
    );

    // 4. Log activity
    logUserActivity(
      user.id,
      user.name,
      user.email,
      ip,
      'Requested password reset'
    );

    // 5. Reset URL
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    // 6. Send email using shared sendEmail()
    await sendEmail({
      to: email,
      subject: "Password Reset Request",
      text: `Click the link below to reset your password:\n${resetUrl}\n\nThis link is valid for 1 hour.`,
      html: `
        <p>Hello ${user.name},</p>
        <p>Click the link below to reset your password:</p>
        <p><a href="${resetUrl}">${resetUrl}</a></p>
        <p>This link is valid for 1 hour.</p>
      `,
    });

    return res.json({ message: 'Reset link sent to email' });

  } catch (err) {
    console.error('Forgot Password Error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};



exports.resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;

  console.log("Reset Password Request:", req.body);

  if (!token || !newPassword) {
    return res.status(400).json({ message: "Token and new password are required" });
  }

  if (!validatePassword(newPassword)) {
    return res.status(400).json({ message: "Weak password format" });
  }

  try {
    // 1. Fetch users whose token is still valid
    const [users] = await db.query(
      "SELECT id, reset_token, reset_token_expiry FROM users WHERE reset_token IS NOT NULL AND reset_token_expiry > NOW()"
    );

    if (!users.length) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    // 2. Compare the hashed token
    let matchedUser = null;

    for (const u of users) {
      const isMatch = bcrypt.compareSync(token, u.reset_token);
      if (isMatch) {
        matchedUser = u;
        break;
      }
    }

    if (!matchedUser) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    // 3. Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // 4. Update user password
    await db.query(
      `UPDATE users 
       SET password = ?, reset_token = NULL, reset_token_expiry = NULL 
       WHERE id = ?`,
      [hashedPassword, matchedUser.id]
    );

    return res.json({ message: "Password updated successfully" });

  } catch (err) {
    console.error(" Reset Password Error:", err);
    return res.status(500).json({ message: "Server error" });
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




