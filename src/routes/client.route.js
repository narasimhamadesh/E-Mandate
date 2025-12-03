const express = require("express");
const { addClient, getClients } = require("../controllers/client.controller");

const {
    authenticatedUser,
    authorisedRole,
  } = require("../middleware/auth.middleware");
  

const router = express.Router();

router.post("/",authenticatedUser, authorisedRole("admin"), addClient);
router.get("/", authenticatedUser, authorisedRole("admin"),getClients);

module.exports = router;
