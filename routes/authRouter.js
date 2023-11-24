const express = require("express");
const router = express.Router();

const { 
    login, 
    _logout
} = require("../controllers/authController")

// const { isAuthenticatedUser } = require("../middleware/auth")

router.route("/login").post(login);
// router.route("/_logout").get(isAuthenticatedUser, logout);
router.route("/_logout").get(_logout);

module.exports = router;