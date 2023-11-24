const express = require("express")
const router = express.Router()

const { getUsers, getUser, toggleUserStatus, updateUser, updateUserEmail, updateUserPassword } = require("../controllers/userController")
const { isAuthenticatedUser, authorizeRoles } = require("../middleware/auth")

router.route("/getUsers").get(isAuthenticatedUser, getUsers)
router.route("/getUser/:username").get(isAuthenticatedUser, getUser)
router.route("/toggleUserStatus/:username").put(isAuthenticatedUser, authorizeRoles("admin"), toggleUserStatus)
router.route("/updateUser/:username").put(isAuthenticatedUser, authorizeRoles("admin"), updateUser)
router.route("/updateUserEmail/:username").put(isAuthenticatedUser, updateUserEmail)
router.route("/updateUserPassword/:username").put(isAuthenticatedUser, updateUserPassword)

module.exports = router
