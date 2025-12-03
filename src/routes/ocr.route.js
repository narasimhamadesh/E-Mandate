const express = require("express");
const multer = require("multer");
const router = express.Router();
const { extractTextFromImage } = require("../controllers/ocrMandate.controller");

const {authenticatedUser,
    authorisedRole}= require('../middleware/auth.middleware');

 
// Multer setup
const upload = multer({ dest: "uploads/" });
 
// Route
router.post("/upload",authenticatedUser,authorisedRole("admin"), upload.single("file"), extractTextFromImage);
 
module.exports = router;