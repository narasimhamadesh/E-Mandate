const db = require("../db");
const axios = require("axios");
const path = require("path");
const fs = require("fs");
const { sendMandateEmail } = require("../services/email.service");
const { extractTextFromImage } = require("../utils/ocrFile");
const generateMandateId = require("../utils/generateMandateId");
const { validateIFSCDetails } = require("../services/ifsc.service");


// Time (in minutes) before a Pending mandate auto-fails
const MANDATE_EXPIRY_MINS = 1;




// exports.createMandate = async (req, res) => {
//     const {
//         mobileNumber,
//         fullName,
//         email,
//         loanAmount,
//         bankName,
//         paymentType,
//         accountNumber,
//         accountType,
//         ifscCode,
//         branchName,
//         mandateAmount,
//         maximumCollectionAmount,
//         collectionType,
//         frequency,
//         collectionFirstDate,
//         collectionLastDate,
//         signature,
//         userId,
//     } = req.body;

//     const mandateId = generateMandateId(); // ✅ Generate here

//     try {
//         await validateIFSCDetails(ifscCode, bankName, branchName);

//         const sql = `
//           INSERT INTO e_mandates (
//             mandateId, mobile_number, full_name, email, loan_amount,
//             bank_name, payment_type, account_number, account_type, ifsc_code,
//             branch_name, mandate_amount, max_collection_amount, collection_type,
//             frequency, collection_first_date, collection_last_date, signature,
//             approval_status, user_id, created_at
//           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
//         `;

//         db.query(
//             sql,
//             [
//                 mandateId,
//                 mobileNumber,
//                 fullName,
//                 email,
//                 loanAmount,
//                 bankName,
//                 paymentType,
//                 accountNumber,
//                 accountType,
//                 ifscCode,
//                 branchName,
//                 mandateAmount,
//                 maximumCollectionAmount,
//                 collectionType,
//                 frequency,
//                 collectionFirstDate,
//                 collectionLastDate,
//                 signature,
//                 "Pending",
//                 userId,
//             ],
//             async (err, result) => {
//                 if (err) {
//                     console.error("Database Error:", err);
//                     return res.status(500).json({ error: "Failed to create mandate" });
//                 }

//                 // ✅ Send the email after mandate is inserted
//                 await sendMandateEmail(email, fullName, mandateId);

//                 // ✅ Then respond to frontend
//                 res.status(201).json({
//                     message: "E-Mandate created successfully",
//                     mandateId,
//                     bankName,
//                     branchName,
//                 });
//             }
//         );
//     } catch (error) {
//         console.error("Validation Error:", error);
//         res.status(400).json({ error: error.message });
//     }
// };


exports.createMandate = async (req, res) => {
  const {
      mobileNumber,
      fullName,
      email,
      loanAmount,
      bankName,
      paymentType,
      accountNumber,
      accountType,
      ifscCode,
      branchName,
      mandateAmount,
      maximumCollectionAmount,
      collectionType,
      frequency,
      collectionFirstDate,
      collectionLastDate,
      signature,
      userId,
  } = req.body;

  const mandateId = generateMandateId();

  try {
      // Validate IFSC before inserting
      await validateIFSCDetails(ifscCode, bankName, branchName);

      const sql = `
        INSERT INTO e_mandates (
          mandateId, mobile_number, full_name, email, loan_amount,
          bank_name, payment_type, account_number, account_type,
          ifsc_code, branch_name, mandate_amount, max_collection_amount,
          collection_type, frequency, collection_first_date, collection_last_date,
          signature, approval_status, user_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
      `;

      const params = [
          mandateId,
          mobileNumber,
          fullName,
          email,
          loanAmount,
          bankName,
          paymentType,
          accountNumber,
          accountType,
          ifscCode,
          branchName,
          mandateAmount,
          maximumCollectionAmount,
          collectionType,
          frequency,
          collectionFirstDate,
          collectionLastDate,
          signature,
          "Pending",
          userId,
      ];

      // ❗ FIX: Use await instead of callback
      const [result] = await db.query(sql, params);

      // Send email after insert
      await sendMandateEmail(email, fullName, mandateId);

      return res.status(201).json({
          message: "E-Mandate created successfully",
          mandateId,
          bankName,
          branchName,
      });

  } catch (error) {
      console.error("Create Mandate Error:", error);
      return res.status(400).json({ error: error.message || "Something went wrong" });
  }
};


exports.getMandateById = (req, res) => {
    const { mandateId } = req.params;
    const query = "SELECT * FROM e_mandates WHERE mandateId = ?";
    db.query(query, [mandateId], (err, results) => {
        if (err) {
            console.error("Error fetching mandate by ID:", err);
            return res.status(500).json({ error: "Database error" });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: "Mandate not found" });
        }
        res.status(200).json(results[0]);
    });
};

 
exports.bulkUploadMandates = async (req, res) => {
  const { mandates } = req.body;
 
  if (!mandates || !Array.isArray(mandates)) {
    return res.status(400).json({ error: "Invalid or empty mandates array" });
  }
 
  // Validate all records first
  try {
    const validationPromises = mandates.map(async (mandate, index) => {
      if (!mandate.userId)
        throw new Error(`Record ${index + 1}: Missing userId`);
      if (!mandate.ifscCode || mandate.ifscCode.length !== 11) {
        throw new Error(`Record ${index + 1}: Invalid IFSC code`);
      }
      if (!mandate.branchName)
        throw new Error(`Record ${index + 1}: Missing branchName`);
 
      await validateIFSCDetails(
        mandate.ifscCode,
        mandate.bankName,
        mandate.branchName
      );
    });
 
    await Promise.all(validationPromises);
 
    const values = mandates.map((m) => [
      m.loanNumber || "",
      m.mobileNumber || "",
      m.fullName || "",
      m.email || "",
      m.loanAmount || 0,
      m.bankName || "",
      m.paymentType || "",
      m.accountNumber || "",
      m.accountType || "",
      m.ifscCode || "",
      m.branchName || "",
      m.mandateAmount || 0,
      m.maximumCollectionAmount || 0,
      m.collectionType || "",
      m.frequency || "",
      m.collectionFirstDate ? new Date(m.collectionFirstDate) : null,
      m.collectionLastDate ? new Date(m.collectionLastDate) : null,
      m.signature || null,
      "Pending",
      new Date(),
      m.userId,
    ]);
 
    const sql = `
      INSERT INTO e_mandates (
        loan_number, mobile_number, full_name, email, loan_amount,
        bank_name, payment_type, account_number, account_type, ifsc_code,
        branch_name, mandate_amount, max_collection_amount, collection_type,
        frequency, collection_first_date, collection_last_date,signature,
        approval_status, created_at, user_id
      ) VALUES ?
    `;
 
    db.query(sql, [values], (err, result) => {
      if (err) {
        console.error("Bulk Insert Error:", err);
        return res
          .status(500)
          .json({ error: "Failed to bulk insert mandates" });
      }
      res.status(200).json({
        message: `${result.affectedRows} mandates uploaded successfully`,
      });
    });
  } catch (error) {
    console.error("Bulk Upload Validation Error:", error);
    res.status(400).json({ error: error.message });
  }
};
 
// / Helper function to extract fields using regex
const parseMandateText = (text) => {
  // Adjust these regex patterns to match your document format.
  const getField = (label) => {
    const regex = new RegExp(label + "\\s*:\\s*(.+)", "i");
    const match = text.match(regex);
    return match ? match[1].trim() : null;
  };
 
  return {
    loanNumber: getField("Loan Number", text),
    mobileNumber: getField("Mobile Number", text),
    fullName: getField("Full Name", text),
    email: getField("Email", text) || getField("Email ID", text),
    loanAmount: getField("Loan Amount", text),
    bankName: getField("Bank Name", text),
    paymentType: getField("Payment Type", text), // add this field
    accountNumber: getField("Account Number", text),
    accountType: getField("Account Type", text), // add this field
    ifscCode: getField("IFSC Code", text),
    branchName: getField("Branch Name", text),
    mandateAmount: getField("Mandate Amount", text),
    maxCollectionAmount: getField("Maximum Collection Amount", text), // add this field
    collectionType: getField("Collection Type", text), // add this field
    frequency: getField("Frequency", text), // add this field
    collectionFirstDate: getField("Collection First Date", text),
    collectionLastDate: getField("Collection Last Date", text),
  };
};
 
exports.uploadAndProcessFile = async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded." });
  }
 
  console.log("Uploaded file details:", req.file);
 
  // Build full file path from uploads directory
  const filePath = path.join(__dirname, "../uploads", req.file.filename);
 
  // Only process image files: check mimetype (e.g., image/jpeg, image/png)
  const allowedTypes = ["image/jpeg", "image/png"];
  if (!allowedTypes.includes(req.file.mimetype)) {
    // Delete the uploaded file if not allowed
    fs.unlink(filePath, () => {});
    return res
      .status(400)
      .json({ error: "Only image files (JPEG, PNG) are allowed." });
  }
 
  try {
    // Extract text from the image using OCR
    const extractedText = await extractTextFromImage(filePath);
    console.log("Extracted Text:", extractedText);
 
    // Parse the text to extract mandate fields
    const mandateData = parseMandateText(extractedText);
    console.log("Parsed Mandate Data:", mandateData);
 
    // Validate required fields
    if (
      !mandateData.loanNumber ||
      !mandateData.mobileNumber ||
      !mandateData.fullName ||
      !mandateData.email ||
      !mandateData.loanAmount ||
      !mandateData.bankName ||
      !mandateData.accountNumber ||
      !mandateData.ifscCode ||
      !mandateData.branchName ||
      !mandateData.mandateAmount ||
      !mandateData.collectionFirstDate ||
      !mandateData.collectionLastDate
    ) {
      return res
        .status(400)
        .json({ error: "Extracted data is missing required fields." });
    }
 
    // Insert data into database. Adjust SQL to match your DB schema.
    const sql = ` INSERT INTO e_mandates
        (
          loan_number,mobile_number,full_name,email,loan_amount,bank_name,
          payment_type,account_number,account_type,ifsc_code,branch_name,mandate_amount,
          max_collection_amount,collection_type,frequency,collection_first_date,collection_last_date,approval_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending')`;
    const values = [
      mandateData.loanNumber,
      mandateData.mobileNumber,
      mandateData.fullName,
      mandateData.email,
      mandateData.loanAmount,
      mandateData.bankName,
      mandateData.paymentType,
      mandateData.accountNumber,
      mandateData.accountType,
      mandateData.ifscCode,
      mandateData.branchName,
      mandateData.mandateAmount,
      mandateData.maxCollectionAmount, // instead of null
      mandateData.collectionType, // instead of null
      mandateData.frequency, // instead of null
      mandateData.collectionFirstDate,
      mandateData.collectionLastDate,
    ];
 
    db.query(sql, values, (err, result) => {
      // Optionally remove the file after processing
      fs.unlink(filePath, (unlinkErr) => {
        if (unlinkErr) console.error("Error removing file:", unlinkErr);
      });
 
      if (err) {
        console.error("Database Error:", err);
        return res.status(500).json({ error: "Failed to save mandate data." });
      }
      return res
        .status(201)
        .json({ message: "Mandate data extracted and saved successfully." });
    });
  } catch (error) {
    console.error("Error processing file:", error);
    return res
      .status(500)
      .json({ error: "Error processing the uploaded file." });
  }
};




exports.getUserMandates = (req, res) => {
    const { userId } = req.params; // Get userId from request params
    if (!userId) {
        return res.status(400).json({ error: "User ID is required." });
    }
    const sql = "SELECT * FROM e_mandates WHERE user_id = ?";
    db.query(sql, [userId], (err, result) => {
        if (err) {
            console.error("Error fetching user mandates:", err);
            return res.status(500).json({ error: "Failed to fetch mandates." });
        }
        res.json(result);
    });
};




exports.getAllMandates = async (req, res) => {
  try {
      const { userId } = req.params;

      let sql = "SELECT * FROM e_mandates";
      let params = [];

      if (userId && userId !== "0001") {
          sql = "SELECT * FROM e_mandates WHERE user_id = ?";
          params = [userId];
      }

      const [result] = await db.query(sql, params);

      return res.status(200).json(result);

  } catch (err) {
      console.error("Error fetching mandates:", err);
      return res.status(500).json({ error: "Failed to fetch mandates." });
  }
};


// Edit mandate
exports.editMandate = (req, res) => {
  const { id } = req.params;
  const { account_number, mandate_amount, approval_status } = req.body;
  const sql = `
      UPDATE e_mandates
      SET  account_number = ?, mandate_amount = ?, approval_status = ?,updated_at = NOW()
      WHERE id = ?`;
  db.query(
    sql,
    [account_number, mandate_amount, approval_status, id],
    (err, result) => {
      if (err) {
        console.error("Error updating mandate:", err);
        return res.status(500).json({ error: "Failed to update mandate." });
      }
      res.json({ message: "Mandate updated successfully." });
    }
  );
};
 
// Approve mandate
exports.approveMandate = (req, res) => {
  const { id } = req.params;
  const sql =
    "UPDATE e_mandates SET approval_status = 'Approved' updated_at = NOW() WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("Database Error:", err);
      return res.status(500).json({ error: "Failed to approve mandate." });
    }
    res.json({ message: "Mandate approved successfully." });
  });
};
 
// Delete mandate
exports.deleteMandate = (req, res) => {
  const { id } = req.params;
 
  const sql = "DELETE FROM e_mandates WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("Error deleting mandate:", err);
      return res.status(500).json({ error: "Failed to delete mandate." });
    }
    res.json({ message: "Mandate deleted successfully." });
  });
};
 






// Bulk delete mandates
exports.bulkDeleteMandates = (req, res) => {
  const { ids } = req.body;
 
  if (!ids || ids.length === 0) {
    return res
      .status(400)
      .json({ error: "No mandates selected for deletion." });
  }
 
  const sql = "DELETE FROM e_mandates WHERE id IN (?)";
  db.query(sql, [ids], (err, result) => {
    if (err) {
      console.error("Error bulk deleting mandates:", err);
      return res.status(500).json({ error: "Failed to bulk delete mandates." });
    }
    res.json({ message: `${ids.length} mandates deleted successfully.` });
  });
};


exports.authorize = async (req, res) => {
    const { mandateId, method } = req.body;

    if (!mandateId || !method) {
        return res.status(400).json({ error: "mandateId and method are required" });
    }

    try {
        // 1. Fetch mandate status
        const [rows] = await db.promise().query(
            "SELECT approval_status FROM e_mandates WHERE mandateId = ?",
            [mandateId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: "Mandate not found" });
        }

        const currentStatus = rows[0].approval_status;

        // Only pending mandates can be authorized
        if (currentStatus !== "Pending") {
            return res.status(400).json({
                error: `Mandate cannot be authorized. Current status: ${currentStatus}`
            });
        }

        // 2. Update mandate as authorized
        await db.promise().query(
            `UPDATE e_mandates 
             SET authorization_method = ?, 
                 approval_status = 'AUTHORIZED', 
                 status = 'AUTHORIZED', 
                 authorized_at = NOW() 
             WHERE mandateId = ?`,
            [method, mandateId]
        );

        return res.status(200).json({
            message: "Mandate authorized successfully",
            mandateId,
            method
        });

    } catch (error) {
        console.error("Authorization error:", error);
        return res.status(500).json({ error: "Authorization failed", details: error.message });
    }
};
