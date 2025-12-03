const express = require("express");
const router = express.Router();

const {
  getBanks,
  addBank,
  updateBank,
  deleteBank,
  bulkDeleteBanks,
} = require("../controllers/bank.controller");

const {
  authenticatedUser,
  authorisedRole,
} = require("../middleware/auth.middleware");


// Get all banks (Admin only)
router.get("/", authenticatedUser, authorisedRole("admin"), getBanks);

// Add bank
router.post("/", authenticatedUser, authorisedRole("admin"), addBank);

// Update bank
router.put("/:id", authenticatedUser, authorisedRole("admin"), updateBank);

// Delete single bank
router.delete("/:id", authenticatedUser, authorisedRole("admin"), deleteBank);

// Bulk delete
router.post("/bulk-delete",authenticatedUser,authorisedRole("admin"),bulkDeleteBanks);

module.exports = router;
