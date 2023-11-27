const express = require("express")
const router = express.Router()

const { loginUser, logout, registerUser } = require("../controllers/authController")
const { isAuthenticatedUser, authorizeRoles } = require("../middleware/auth")
const { createGroup } = require("../controllers/groupController")

router.route("/login").post(loginUser)
router.route("/logout").get(isAuthenticatedUser, logout)
router.route("/register").post(isAuthenticatedUser, authorizeRoles("admin"), registerUser)
router.route("/createGroup").post(isAuthenticatedUser, authorizeRoles("admin"), createGroup)

module.exports = router
