const express = require("express");
const router = express.Router();
const axios = require('axios');
const {authenticatedUser,
  authorisedRole}= require('../middleware/auth.middleware');

const { getTransactionStatus, generateUMRN , registerMandate,failureResponse } = require("../controllers/npci.controller");


router.post("/transaction-status", authenticatedUser,getTransactionStatus);

router.post("/umrn",authenticatedUser,authorisedRole("admin"), generateUMRN);
router.post("/register",authenticatedUser,authorisedRole("admin"), registerMandate);
router.post("/failure",authenticatedUser, failureResponse);


module.exports = router;
