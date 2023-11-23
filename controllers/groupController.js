const connection = require("../config/database")
const catchAsyncErrors = require("../middleware/catchAsyncErrors")
const ErrorResponse = require("../utils/errorHandler")

// Create a group => /groupController/createGroup
exports.createGroup = catchAsyncErrors(async (req, res, next) => {
  const { name } = req.body

  const result = await connection.promise().execute("INSERT INTO `group` (name) VALUES (?)", [name])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to create group", 500))
  }

  res.status(200).json({
    success: true,
    message: "Group created successfully"
  })
})
