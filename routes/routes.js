const express = require("express")
const router = express.Router()

const { isAuthenticatedUser, authorizeRoles } = require("../middleware/auth")
const { Checkgroup, checkLogin, loginUser, logout, registerUser, getUsers, getUser, toggleUserStatus, updateUser, updateUserEmail, updateUserPassword, createGroup, getGroups } = require("../controllers/controllers")
const { getApplications, createApplication, updateApplication, getApplication, createTask, getTasks, getTask, getTasksByApp, updateNotes, promoteTask, rejectTask, returnTask, getPlan, getPlanByApp } = require("../controllers/controllers")

/*
Auth Controllers
*/
router.route("/login").post(loginUser)
router.route("/_logout").get(isAuthenticatedUser, logout)
router.route("/register").post(isAuthenticatedUser, authorizeRoles("admin"), registerUser)

/*
Group Controllers
*/
router.route("/createGroup").post(isAuthenticatedUser, authorizeRoles("admin"), createGroup)
router.route("/getGroups").get(isAuthenticatedUser, getGroups)

/*
User Controllers
*/
router.route("/getUsers").get(isAuthenticatedUser, getUsers)
router.route("/getUser").get(isAuthenticatedUser, getUser)
router.route("/toggleUserStatus/:username").put(isAuthenticatedUser, authorizeRoles("admin"), toggleUserStatus)
router.route("/updateUser/:username").put(isAuthenticatedUser, authorizeRoles("admin"), updateUser)
router.route("/updateUserEmail/").put(isAuthenticatedUser, updateUserEmail)
router.route("/updateUserPassword/").put(isAuthenticatedUser, updateUserPassword)

/*
Auth Controller
*/
router.route("/checkGroup").post(isAuthenticatedUser, async (req, res, next) => {
  const username = req.user.username
  const group = req.body.group

  const result = await Checkgroup(username, group)
  res.json(result)
})

router.route("/checkLogin").get(isAuthenticatedUser, async (req, res, next) => {
  const token = req.token
  const result = await checkLogin(token)
  res.json(result)
})

/*
Assignment 2 stuff below.
*/
router.route("/getApplications").get(isAuthenticatedUser, getApplications)
router.route("/getApplication/:App_Acronym").get(isAuthenticatedUser, getApplication)
router.route("/getTasksByApp/:App_Acronym").get(isAuthenticatedUser, getTasksByApp)
router.route("/getTasks").get(isAuthenticatedUser, getTasks)
router.route("/getTask/:Task_id").get(isAuthenticatedUser, getTask)
router.route("/createApplication").post(isAuthenticatedUser, createApplication)
router.route("/updateApplication/:App_Acronym").put(isAuthenticatedUser, updateApplication)
router.route("/createTask").post(isAuthenticatedUser, createTask)
router.route("/updateNotes/:Task_id").put(isAuthenticatedUser, updateNotes)
router.route("/promoteTask/:Task_id").put(isAuthenticatedUser, promoteTask)
router.route("/rejectTask/:Task_id").put(isAuthenticatedUser, rejectTask)
router.route("/returnTask/:Task_id").put(isAuthenticatedUser, returnTask)
router.route("/getPlan/").post(isAuthenticatedUser, getPlan)
router.route("/getPlanByApp/:App_Acronym").get(isAuthenticatedUser, getPlanByApp)

module.exports = router
