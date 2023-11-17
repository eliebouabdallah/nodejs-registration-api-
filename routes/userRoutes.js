const express = require("express");
const router = express.Router();

const fetchController = require("../controllers/fetchUsersController");
const userController = require("../controllers/userController");
router.get("/fetchusers",userController.protect, fetchController.getAllUsers);

module.exports = router;
