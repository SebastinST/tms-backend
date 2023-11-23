const connection = require("../config/database")

exports.loginUser = async (req, res, next) => {
  const { username, password } = req.body

  if (!username || !password) {
    return next(new ErrorResponse("Please provide an username and password", 400))
  }

  //find user in database
  connection.query("SELECT * FROM user WHERE username = ?", [username], async (error, result) => {
    if (error) {
      return next(new ErrorResponse("Internal Server Error", 500))
    }

    if (result.length === 0) {
      return next(new ErrorResponse("User does not exist", 401))
    }

    const user = result[0]

    if (user.password !== password) {
      return next(new ErrorResponse("Invalid credentials", 401))
    }

    res.status(200).json({
      success: true,
      data: user
    })
  })
}
