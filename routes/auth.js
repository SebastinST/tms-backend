const express = require("express")
const router = express.Router()

const { loginUser, logout, registerUser } = require("../controllers/authController")
const { isAuthenticatedUser, authorizeRoles } = require("../middleware/auth")

router.route("/login").post(loginUser)
router.route("/logout").get(isAuthenticatedUser, logout)
router.route("/register").post(isAuthenticatedUser, authorizeRoles("admin"), registerUser)

module.exports = router
