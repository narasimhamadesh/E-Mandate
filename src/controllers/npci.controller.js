const axios = require("axios");

// Change based on ENV (Production / UAT)
const NPCI_URL = process.env.NPCI_ENV === "PROD"
  ? "https://enach.npci.org.in/apiservices/getTransStatusForBanks"
  : "https://103.14.161.144/8086/apiservices/getTransStatusForBanks";

exports.getTransactionStatus = async (req, res) => {
  try {
    const { npcirefmsgID } = req.body;

    if (!npcirefmsgID || !Array.isArray(npcirefmsgID)) {
      return res.status(400).json({
        status: false,
        message: "npcirefmsgID must be an array"
      });
    }

    // Prepare JSON payload to send to NPCI
    const payload = {
      npcirefmsgID: npcirefmsgID
    };

    console.log("Request Sent to NPCI:", payload);

    const response = await axios.post(NPCI_URL, payload, {
      headers: {
        "Content-Type": "application/json"
      },
      timeout: 30000 // 30 seconds
    });

    console.log("NPCI Response:", response.data);

    return res.status(200).json({
      status: true,
      data: response.data
    });

  } catch (error) {
    console.error("NPCI Error:", error);

    return res.status(500).json({
      status: false,
      message: "Failed to fetch transaction status",
      error: error.message
    });
  }
};

// controllers/npci.controller.js

// Generate random UMRN
exports.generateUMRN = (req, res) => {
    const { customerName, accountNumber } = req.body;
    const umrn = "NPCI" + Math.floor(Math.random() * 1000000000);
  
    res.json({
      status: "success",
      message: "UMRN generated successfully",
      data: {
        umrn,
        customerName,
        accountNumber,
        timestamp: new Date().toISOString(),
      },
    });
  };
  
  // Registration response
  exports.registerMandate = (req, res) => {
    const { umrn } = req.body;
  
    res.json({
      status: "registered",
      message: "Mandate registered with NPCI",
      data: {
        umrn,
        registrationStatus: "Success",
        mandateStartDate: new Date().toISOString().slice(0, 10),
        mandateEndDate: "2030-12-31",
      },
    });
  };
  
  // Failure simulation
  exports.failureResponse = (req, res) => {
    res.status(400).json({
      status: "failed",
      message: "Invalid mandate data",
      errorCode: "NPCI_ERR_400",
    });
  };
  