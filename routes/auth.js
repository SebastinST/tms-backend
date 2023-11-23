const express = require("express")
const router = express.Router()

const { loginUser } = require("../controllers/authController")

router.route('/login').post(loginUser)

module.exports = router;