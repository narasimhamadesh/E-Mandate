const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const axios = require('axios');
const os = require('os');
const requestIp = require('request-ip');
const nodemailer = require('nodemailer');

const db = require('../db');
const config = require('../config');




// -----------------------------------------------
// GET ALL BANKS
// -----------------------------------------------
exports.getBanks = async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM banks");
    // console.log("Fetched banks:", rows);
    return res.json(rows);
  } catch (err) {
    console.error("Error fetching banks:", err);
    return res.status(500).json({ message: "Server error", error: err.message });
  }
};

// -----------------------------------------------
// ADD A NEW BANK
// -----------------------------------------------
exports.addBank = async (req, res) => {
  const { code, bank_name, netbanking, debit_card, aadhaar } = req.body;

  if (!code || !bank_name) {
    return res.status(400).json({ message: "code & bank_name are required" });
  }

  try {
    const sql =
      "INSERT INTO banks (code, bank_name, netbanking, debit_card, aadhaar) VALUES (?, ?, ?, ?, ?)";

    const [result] = await db.query(sql, [
      code,
      bank_name,
      netbanking || 0,
      debit_card || 0,
      aadhaar || 0,
    ]);

    return res.json({
      message: "Bank added successfully",
      insertedId: result.insertId,
    });
  } catch (err) {
    console.error("Error adding bank:", err);
    return res.status(500).json({ message: "Server error", error: err.message });
  }
};

// -----------------------------------------------
// UPDATE BANK
// -----------------------------------------------
exports.updateBank = async (req, res) => {
  const { id } = req.params;
  const { code, bank_name, netbanking, debit_card, aadhaar } = req.body;

  try {
    const sql =
      "UPDATE banks SET code=?, bank_name=?, netbanking=?, debit_card=?, aadhaar=? WHERE id=?";

    await db.query(sql, [
      code,
      bank_name,
      netbanking,
      debit_card,
      aadhaar,
      id,
    ]);

    return res.json({ message: "Bank updated successfully" });
  } catch (err) {
    console.error("Error updating bank:", err);
    return res.status(500).json({ message: "Server error", error: err.message });
  }
};

// -----------------------------------------------
// DELETE A SINGLE BANK
// -----------------------------------------------
exports.deleteBank = async (req, res) => {
  const { id } = req.params;

  try {
    await db.query("DELETE FROM banks WHERE id=?", [id]);
    return res.json({ message: "Bank deleted successfully" });
  } catch (err) {
    console.error("Error deleting bank:", err);
    return res.status(500).json({ message: "Server error", error: err.message });
  }
};

// -----------------------------------------------
// BULK DELETE BANKS
// -----------------------------------------------
exports.bulkDeleteBanks = async (req, res) => {
  const { ids } = req.body;

  if (!ids || !Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ message: "Provide valid bank IDs" });
  }

  try {
    const placeholders = ids.map(() => "?").join(",");

    const sql = `DELETE FROM banks WHERE id IN (${placeholders})`;

    await db.query(sql, ids);

    return res.json({
      message: "Bulk delete successful",
      deletedCount: ids.length,
    });
  } catch (err) {
    console.error("Error bulk deleting banks:", err);
    return res.status(500).json({ message: "Server error", error: err.message });
  }
};



