const express = require("express");
const router = express.Router();
const umrnController = require("../controllers/umrn.controller");

const {
    authenticatedUser,
    authorisedRole,
  } = require("../middleware/auth.middleware");

// Save UMRN
// router.post("/save-umrn",authenticatedUser, authorisedRole("admin"), umrnController.saveUMRN);
router.post("/save-umrn",umrnController.saveUMRN);

// Get UMRN by mandate ID
router.get("/mandate/:mandateId",authenticatedUser, authorisedRole("admin"), umrnController.getUMRNByMandateId);

// Get UMRN by UMRN number
router.get("/number/:umrnNumber",authenticatedUser, authorisedRole("admin"), umrnController.getUMRNByNumber);

// Get all UMRNs (admin)
router.get("/",authenticatedUser, authorisedRole("admin"), umrnController.getAllUMRNs);

// Cancel UMRN
router.put("/cancel/:umrnNumber",authenticatedUser, authorisedRole("admin"), umrnController.cancelUMRN);

// OTP routes
router.post("/send-otp", umrnController.sendOTP);
router.post("/verify-otp", umrnController.verifyOTP);

module.exports = router;
