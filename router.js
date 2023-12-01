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
    toggleUserStatus
} = require("./controller");

const { isUserValid, authorizedGroups, protectAdmin, checkingGroup } = require("./auth")

// All user routes
router.route("/login").post(login);
router.route("/_logout").get(_logout);
router.route("/getSelf").get(isUserValid, getSelf);
router.route("/updateSelf").post(isUserValid, updateSelf);

// Admin routes
router.route("/createGroup").post(isUserValid, authorizedGroups("admin"), createGroup);
router.route("/createUser").post(isUserValid, authorizedGroups("admin"), createUser);
router.route("/getAllUsers").get(isUserValid, authorizedGroups("admin"), getAllUsers);
router.route("/getAllGroups").get(isUserValid, authorizedGroups("admin"), getAllGroups);

// Root Admin protected routes
router.route("/updateUser").post(isUserValid, authorizedGroups("admin"), protectAdmin, updateUser);
router.route("/toggleUserStatus").post(isUserValid, authorizedGroups("admin"), protectAdmin, toggleUserStatus);

// Specification route
router.route("/Checkgroup").post(isUserValid, checkingGroup);

module.exports = router;