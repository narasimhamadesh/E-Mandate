const express = require("express");
const { getUserLogs } = require("../controllers/userlog.controller");
const {authenticatedUser,authorisedRole}= require('../middleware/auth.middleware');
const router = express.Router();

// Route to get user logs (only accessible to admins)
router.get("/userlogs",authenticatedUser,authorisedRole("admin"), getUserLogs);

module.exports = router;
