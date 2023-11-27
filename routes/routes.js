const express = require("express");
const router = express.Router();

const { isAuthenticatedUser, authorizeRoles } = require("../middleware/auth");
const {
  checkGroup,
  checkLogin,
  loginUser,
  logout,
  registerUser,
  getUsers,
  getUser,
  toggleUserStatus,
  updateUser,
  updateUserEmail,
  updateUserPassword,
  createGroup,
} = require("../controllers/controllers");

router.route("/login").post(loginUser)
router.route("/_logout").get(isAuthenticatedUser, logout)
router.route("/register").post(isAuthenticatedUser, authorizeRoles("admin"), registerUser)
router.route("/createGroup").post(isAuthenticatedUser, authorizeRoles("admin"), createGroup)

router.route("/getUsers").get(isAuthenticatedUser, getUsers);
router.route("/getUser/:username").get(isAuthenticatedUser, getUser);
router
  .route("/toggleUserStatus/:username")
  .put(isAuthenticatedUser, authorizeRoles("admin"), toggleUserStatus);
router
  .route("/updateUser/:username")
  .put(isAuthenticatedUser, authorizeRoles("admin"), updateUser);
router
  .route("/updateUserEmail/")
  .put(isAuthenticatedUser, updateUserEmail);
router
  .route("/updateUserPassword/")
  .put(isAuthenticatedUser, updateUserPassword);

router.route("/checkGroup").get(async (req, res, next) => {
  const username = req.query.username;
  const group = req.query.group;

  const result = await checkGroup(username, group);
  res.json(result);
});

router.route("/checkLogin").get(async (req, res, next) => {
  const token = req.query.token;
  const result = await checkLogin(token);
  res.json(result);
});

module.exports = router;
