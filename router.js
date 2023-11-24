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
    updateUser
} = require("./controller");

// const { isAuthenticatedUser } = require("../middleware/auth")

router.route("/login").post(login);
router.route("/_logout").get(_logout);
router.route("/getSelf").get(getSelf);
router.route("/updateSelf").post(updateSelf);
router.route("/createGroup").post(createGroup);
router.route("/createUser").post(createUser);
router.route("/getAllUsers").get(getAllUsers);
router.route("/getAllGroups").get(getAllGroups);
router.route("/updateUser").post(updateUser);

module.exports = router;