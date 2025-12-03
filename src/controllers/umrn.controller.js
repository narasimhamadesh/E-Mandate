const db = require("../db");

const generateUMRN = require("../utils/generateUMRN");

// ----------------------------
// Promisify DB Query
// ----------------------------
function promisifiedQuery(sql, params) {
  return new Promise((resolve, reject) => {
    db.query(sql, params, (err, results) => {
      if (err) return reject(err);
      resolve(results);
    });
  });
}

// ----------------------------
// Generate UMRN Number
// ----------------------------

// ----------------------------
// 1. Save UMRN
// ----------------------------
exports.saveUMRN = async (req, res) => {
  console.log("saveUMRN called:", req.body);

  try {
    const { mandateId, authorizationMethod, authorizedAt, status } = req.body;

    if (!mandateId) {
      return res.status(400).json({ success: false, error: "Mandate ID is required" });
    }

    // Check mandate
    const [rows] = await db.query(
      "SELECT approval_status FROM e_mandates WHERE mandateID = ?",
      [mandateId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Mandate not found" });
    }

    if (rows[0].approval_status !== "Pending") {
      return res.status(400).json({
        error: "Mandate is expired or already authorized.",
      });
    }

    const umrnNumber = generateUMRN();
    console.log("Generated UMRN:", umrnNumber);

    const currentTimestamp = new Date()
      .toISOString()
      .slice(0, 19)
      .replace("T", " ");

    // Insert UMRN authorization
    await db.query(
      `
      INSERT INTO umrn_authorizations
      (mandate_id, umrn_number, authorization_method, authorized_at, status)
      VALUES (?, ?, ?, ?, ?)
      `,
      [
        mandateId,
        umrnNumber,
        authorizationMethod || "netBanking",
        authorizedAt || currentTimestamp,
        status || "AUTHORIZED",
      ]
    );

    // Update mandate table
    await db.query(
      `
      UPDATE e_mandates
      SET 
        status='AUTHORIZED',
        approval_status='AUTHORIZED',
        umrn_number=?,
        authorized_at=?
      WHERE mandateID=?
      `,
      [umrnNumber, authorizedAt || currentTimestamp, mandateId]
    );

    return res.status(201).json({
      success: true,
      message: "E-Mandate authorized successfully",
      data: {
        umrnNumber,
        mandateId,
        status: "AUTHORIZED",
        authorizedAt: authorizedAt || currentTimestamp,
      },
    });

  } catch (error) {
    console.error("Error in saveUMRN:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to authorize e-mandate",
      message: error.message,
    });
  }
};


// ----------------------------
// 2. Get UMRN by Mandate ID
// ----------------------------
exports.getUMRNByMandateId = async (req, res) => {
  try {
    const { mandateId } = req.params;

    if (!mandateId) {
      return res.status(400).json({ success: false, error: "Mandate ID is required" });
    }

    const rows = await promisifiedQuery(
      `SELECT ua.*, m.full_name, m.email, m.mobile_number, m.mandate_amount
       FROM umrn_authorizations ua
       LEFT JOIN e_mandates m ON ua.mandate_id = m.mandateID
       WHERE ua.mandate_id = ?
       ORDER BY ua.created_at DESC
       LIMIT 1`,
      [mandateId]
    );

    if (!rows.length) {
      return res.status(404).json({ success: false, error: "UMRN not found" });
    }

    res.json({ success: true, data: rows[0] });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch UMRN",
      message: error.message,
    });
  }
};

// ----------------------------
// 3. Get UMRN by UMRN Number
// ----------------------------
exports.getUMRNByNumber = async (req, res) => {
  try {
    const { umrnNumber } = req.params;

    if (!umrnNumber) {
      return res.status(400).json({ success: false, error: "UMRN Number is required" });
    }

    const rows = await promisifiedQuery(
      `SELECT ua.*, m.full_name, m.email, m.mobile_number,
              m.mandate_amount, m.bank_name, m.account_number
       FROM umrn_authorizations ua
       LEFT JOIN e_mandates m ON ua.mandate_id = m.mandateID
       WHERE ua.umrn_number = ?`,
      [umrnNumber]
    );

    if (!rows.length) {
      return res.status(404).json({ success: false, error: "UMRN not found" });
    }

    res.json({ success: true, data: rows[0] });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch UMRN",
      message: error.message,
    });
  }
};

// ----------------------------
// 4. Get All UMRNs (Admin)
// ----------------------------
exports.getAllUMRNs = async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    const offset = (page - 1) * limit;

    let where = "";
    const params = [];

    if (status) {
      where = "WHERE ua.status = ?";
      params.push(status);
    }

    const rows = await promisifiedQuery(
      `SELECT ua.*, m.full_name, m.email, m.mobile_number, m.bank_name
       FROM umrn_authorizations ua
       LEFT JOIN e_mandates m ON ua.mandate_id = m.mandateID
       ${where}
       ORDER BY ua.created_at DESC
       LIMIT ? OFFSET ?`,
      [...params, Number(limit), Number(offset)]
    );

    const totalRows = await promisifiedQuery(
      `SELECT COUNT(*) as total FROM umrn_authorizations ua ${where}`,
      status ? [status] : []
    );

    res.json({
      success: true,
      data: rows,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: totalRows[0].total,
        totalPages: Math.ceil(totalRows[0].total / limit),
      },
    });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch UMRNs",
      message: error.message,
    });
  }
};

// ----------------------------
// 5. Cancel UMRN
// ----------------------------
exports.cancelUMRN = async (req, res) => {
  try {
    const { umrnNumber } = req.params;
    const { reason } = req.body;

    if (!umrnNumber) {
      return res.status(400).json({ success: false, error: "UMRN number required" });
    }

    const result = await promisifiedQuery(
      `UPDATE umrn_authorizations
       SET status='CANCELLED', updated_at=CURRENT_TIMESTAMP
       WHERE umrn_number=?`,
      [umrnNumber]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, error: "UMRN not found" });
    }

    await promisifiedQuery(
      `UPDATE e_mandates SET status='CANCELLED' WHERE umrn_number=?`,
      [umrnNumber]
    );

    res.json({
      success: true,
      message: "UMRN cancelled successfully",
      data: {
        umrnNumber,
        status: "CANCELLED",
        reason: reason || "User requested cancellation",
      },
    });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to cancel UMRN",
      message: error.message,
    });
  }
};

// ----------------------------
// 6. Send OTP (Demo)
// ----------------------------
exports.sendOTP = async (req, res) => {
  const { mandateId, mobileNumber } = req.body;

  console.log("sendOTP called with:", req.body);

  if (!mandateId || !mobileNumber) {
    return res.status(400).json({
      success: false,
      error: "Mandate ID and mobile number are required",
    });
  }

  // Demo OTP
  return res.json({
    success: true,
    message: "OTP sent",
    data: { mandateId, mobileNumber, otp: "123456" },
  });
};

// ----------------------------
// 7. Verify OTP (Demo)
// ----------------------------
exports.verifyOTP = async (req, res) => {
  const { mandateId, otp } = req.body;

  if (!mandateId || !otp) {
    return res.status(400).json({
      success: false,
      error: "Mandate ID and OTP required",
    });
  }

  if (otp !== "123456") {
    return res.status(400).json({
      success: false,
      error: "Invalid OTP",
    });
  }

  res.json({
    success: true,
    message: "OTP verified",
    data: { verified: true, mandateId },
  });
};
