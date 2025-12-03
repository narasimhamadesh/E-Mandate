// services/ifsc.service.js

const axios = require("axios");

async function validateIFSCDetails(ifscCode, bankName, branchName) {
  const errors = [];

  try {
    const response = await axios.get(`https://ifsc.razorpay.com/${ifscCode}`);
    const data = response.data;

    if (!data.BANK) throw new Error("Invalid bank data from IFSC service");
    if (!data.BRANCH) throw new Error("Invalid branch data from IFSC service");

    if (data.BANK !== bankName) {
      errors.push(`Bank name mismatch: Expected ${data.BANK}, got ${bankName}`);
    }

    if (data.BRANCH !== branchName) {
      errors.push(
        `Branch mismatch: Expected ${data.BRANCH}, got ${branchName}`
      );
    }

    // If mismatches exist
    if (errors.length > 0) {
      return {
        valid: false,
        errors,
      };
    }

    return {
      valid: true,
      bank: data.BANK,
      branch: data.BRANCH,
      bankCode: data.BANKCODE,
    };
  } catch (err) {
    console.error(`IFSC validation failed for ${ifscCode}:`, err.message);

    if (err.response?.status === 404) {
      return {
        valid: false,
        errors: [`Invalid IFSC code '${ifscCode}' (Not Found).`],
      };
    }

    return {
      valid: false,
      errors: [
        `Failed to validate bank details for IFSC ${ifscCode}. Service might be unavailable.`,
      ],
    };
  }
}

module.exports = { validateIFSCDetails };
