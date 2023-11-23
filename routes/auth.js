const express = require("express")
const router = express.Router()

const { loginUser, logout } = require("../controllers/authController")

router.route("/login").post(loginUser)
router.route("/logout").get(logout)

module.exports = router
