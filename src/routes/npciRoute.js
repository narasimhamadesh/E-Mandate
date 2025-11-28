const express = require("express");
const router = express.Router();
const axios = require('axios');

const NPCI_URL = process.env.NPCI_ENV === 'PROD'
  ? 'https://enach.npci.org.in/apiservices/getTransStatusForBanks'
  : 'https://103.14.161.144/8086/apiservices/getTransStatusForBanks';

router.post('/transaction-status', async (req, res) => {
  try {
    const { npcirefmsgID } = req.body;
    if (!npcirefmsgID || !Array.isArray(npcirefmsgID)) {
      return res.status(400).json({ status: false, message: 'npcirefmsgID must be an array' });
    }
    const payload = { npcirefmsgID };
    const response = await axios.post(NPCI_URL, payload, { headers: { 'Content-Type': 'application/json' }, timeout: 60000 });
    return res.json({ status: true, data: response.data });
  } catch (err) {
    console.error('NPCI Error:', err.message || err);
    return res.status(500).json({ status: false, message: 'Failed to fetch transaction status', error: err.message });
  }
});

module.exports = router;
