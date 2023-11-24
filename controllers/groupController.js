const connection = require("../config/database")
const catchAsyncErrors = require("../middleware/catchAsyncErrors")
const ErrorResponse = require("../utils/errorHandler")

// Create a group => /groupController/createGroup
exports.createGroup = catchAsyncErrors(async (req, res, next) => {
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
