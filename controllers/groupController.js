/*const connection = require("../config/database")
const catchAsyncErrors = require("../middleware/catchAsyncErrors")
const ErrorResponse = require("../utils/errorHandler")

// Create a group => /groupController/createGroup
exports.createGroup = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to create group
  const { group_name } = req.body

  //Check if group already exists
  const [row, fields] = await connection.promise().query("SELECT * FROM usergroups WHERE group_name = ?", [group_name])
  if (row.length !== 0) {
    return next(new ErrorResponse("Group already exists", 400))
  }

  //Insert group into database
  const result = await connection.promise().execute("INSERT INTO usergroups (group_name) VALUES (?)", [group_name])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to create group", 500))
  }

  res.status(200).json({
    success: true,
    message: "Group created successfully"
  })
})

// checkGroup(username, group) to check if a user is in a group, we should not export this function
async function checkGroup(username, group) {
  //get user from database
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [username])
  if (row.length === 0) {
    return false
  }
  const user = row[0]
  //User can have multiple groups delimited by ,{group},{group}. We need to split them into an array
  user.group_list = user.group_list.split(",")
  //if any of the user's groups is included in the roles array, then the user is authorized
  authorised = user.group_list.includes(group)
  if (!authorised) {
    return false
  }
  return true
}
*/