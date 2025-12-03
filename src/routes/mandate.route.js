const express = require('express');
const router = express.Router();
const {authenticatedUser,authorisedRole}= require('../middleware/auth.middleware');

const mandateController = require('../controllers/mandate.controller');

const multer = require("multer");
const path = require("path");
 
// Configure Multer to preserve original file extension
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + "-" + uniqueSuffix + ext);
  },
});
const upload = multer({ storage }); 
 
router.post("/mandates",authenticatedUser,authorisedRole("admin"), mandateController.createMandate);
router.get("/mandates/:userId", authenticatedUser,authorisedRole("admin"),mandateController.getAllMandates);
router.put("/mandates/edit/:id",authenticatedUser,authorisedRole("admin"), mandateController.editMandate);
router.put("/mandates/approve/:id",authenticatedUser,authorisedRole("admin"), mandateController.approveMandate);
router.delete("/mandates/delete/:id",authenticatedUser,authorisedRole("admin"), mandateController.deleteMandate);
router.delete("/mandates/delete-bulk", authenticatedUser,authorisedRole("admin"),mandateController.bulkDeleteMandates);
router.post("/bulk-upload", authenticatedUser,authorisedRole("admin"),mandateController.bulkUploadMandates);
router.post("/upload-file",authenticatedUser,authorisedRole("admin"), upload.single("file"), mandateController.uploadAndProcessFile);
router.get("/mandates/user/:userId",authenticatedUser,authorisedRole("admin"), mandateController.getUserMandates);
router.get("/mandates-by-id/:mandateId", authenticatedUser,authorisedRole("admin"),mandateController.getMandateById);
router.post("/authorize", authenticatedUser,authorisedRole("admin"),mandateController.authorize);

 

module.exports = router;