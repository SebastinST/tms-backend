const express = require("express")
const router = express.Router()

const { isAuthenticatedUser, authorizeRoles } = require("../middleware/auth")
const { Checkgroup, checkLogin, loginUser, logout, registerUser, getUsers, getUser, toggleUserStatus, updateUser, updateUserEmail, updateUserPassword, createGroup, getGroups } = require("../controllers/controllers")
const { getApplications, createApplication, updateApplication, getApplication, createTask, getTasks, getTask, getTasksByApp, updateNotes, promoteTask, rejectTask, returnTask, getPlan, getPlanByApp, createPlan, updatePlan, assignTaskToPlan } = require("../controllers/controllers")

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
router.route("/getApplication/:App_Acronym").get(isAuthenticatedUser, getApplication) //Only person who should be accessing this is project lead as they need to edit the application.
router.route("/getTasksByApp/:App_Acronym").get(isAuthenticatedUser, getTasksByApp)
router.route("/getTasks").get(isAuthenticatedUser, getTasks) //Might be redundant/unnecessary
router.route("/getTask/:Task_id").get(isAuthenticatedUser, getTask)
router.route("/createApplication").post(isAuthenticatedUser, createApplication) //Should be restricted to project lead
router.route("/updateApplication/:App_Acronym").put(isAuthenticatedUser, updateApplication) //Should be restricted to project lead
router.route("/createTask").post(isAuthenticatedUser, createTask) //Should be restricted to people with groups inside App_permit_Create
router.route("/updateNotes/:Task_id").put(isAuthenticatedUser, updateNotes) 
router.route("/promoteTask/:Task_id").put(isAuthenticatedUser, promoteTask) //Should be restricted to people with groups inside App_permit_Done
router.route("/rejectTask/:Task_id").put(isAuthenticatedUser, rejectTask) //Should be restricted to people with groups inside App_permit_Done
router.route("/returnTask/:Task_id").put(isAuthenticatedUser, returnTask) //Should be restricted to people with groups inside App_permit_Doing
router.route("/getPlan/").post(isAuthenticatedUser, getPlan) //Should be restricted to project manager
router.route("/getPlanByApp/:App_Acronym").get(isAuthenticatedUser, getPlanByApp) //Should be restricted to project manager
router.route("/createPlan").post(isAuthenticatedUser, createPlan) //Should be restricted to project manager
router.route("/updatePlan").put(isAuthenticatedUser, updatePlan) //Should be restricted to project manager
router.route("/assignTaskToPlan/:Task_id").put(isAuthenticatedUser, assignTaskToPlan) //Should be restricted to project manager

module.exports = router
