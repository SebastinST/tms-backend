const express = require("express")
const router = express.Router()

const { isAuthenticatedUser } = require("../middleware/auth")
const { checkGroup, checkLogin } = require("../controllers/controllers")

router.route("/checkGroup").get(async (req, res, next) => {
  const username = req.query.username
  const group = req.query.group

  const result = await checkGroup(username, group)
  res.json(result)
})

router.route("/checkLogin").get(async (req, res, next) => {
  const token = req.query.token
  const result = await checkLogin(token)
  res.json(result)
})

module.exports = router
