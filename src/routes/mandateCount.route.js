const express = require("express");
const router = express.Router();
const { getMandatesByDateRange } = require("../controllers/mandateCount.controller");
const {authenticatedUser,
    authorisedRole}= require('../middleware/auth.middleware');

router.get("/mandates/stats/:range",authenticatedUser,authorisedRole("admin"), getMandatesByDateRange);
module.exports = router;