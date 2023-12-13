const express = require("express");
const router = express.Router();

const { 
    login, 
    _logout,
    getSelf,
    updateSelf,
    createGroup,
    createUser,
    getAllUsers,
    getAllGroups,
    updateUser,
    toggleUserStatus,
    getAllApps,
    createApp,
    updateApp,
    getPlansByApp,
    createPlan,
    updatePlan,
    getTasksByApp,
    createTask,
    getTaskById,
    addTaskNotes,
    promoteTask,
    rejectTask,
    returnTask,
    assignTaskToPlan
} = require("./controller");

const { isUserValid, authorizedGroups, protectAdmin, checkingGroup } = require("./auth")

// User & Admin routes
router.route("/login").post(login);
router.route("/_logout").get(_logout);
router.route("/getSelf").get(isUserValid, getSelf);
router.route("/updateSelf").post(isUserValid, updateSelf);
router.route("/createGroup").post(isUserValid, authorizedGroups("admin"), createGroup);
router.route("/createUser").post(isUserValid, authorizedGroups("admin"), createUser);
router.route("/getAllUsers").get(isUserValid, authorizedGroups("admin"), getAllUsers);
router.route("/getAllGroups").get(isUserValid, authorizedGroups("admin", "pl"), getAllGroups);
router.route("/updateUser").post(isUserValid, authorizedGroups("admin"), protectAdmin, updateUser);
router.route("/toggleUserStatus").post(isUserValid, authorizedGroups("admin"), protectAdmin, toggleUserStatus);
router.route("/Checkgroup").post(isUserValid, checkingGroup);

// Application routes
router.route("/getAllApps").get(isUserValid, getAllApps);
router.route("/createApp").post(isUserValid, authorizedGroups("pl"), createApp);
router.route("/updateApp").post(isUserValid, authorizedGroups("pl"), updateApp);

// Plan routes
router.route("/getPlansByApp/:App_Acronym").get(isUserValid, authorizedGroups("pm"), getPlansByApp);
router.route("/createPlan").post(isUserValid, authorizedGroups("pm"), createPlan);
router.route("/updatePlan").post(isUserValid, authorizedGroups("pm"), updatePlan);

// Task routes
router.route("/getTasksByApp/:App_Acronym").get(isUserValid, getTasksByApp);
router.route("/createTask").post(isUserValid, createTask);
router.route("/getTaskById/:Task_id").get(isUserValid, getTaskById);
router.route("/addTaskNotes").post(isUserValid, addTaskNotes);
router.route("/promoteTask").post(isUserValid, promoteTask);
router.route("/rejectTask").post(isUserValid, rejectTask);
router.route("/returnTask").post(isUserValid, returnTask);
router.route("/assignTaskToPlan").post(isUserValid, assignTaskToPlan);

module.exports = router;