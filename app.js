const express = require("express")
const app = express()

const dotenv = require("dotenv")

//Setting up config.env file variable
dotenv.config({ path: "./config/config.env" })

//Setting up database connection
const connection = require("./config/database")

/*const query = connection.query("SELECT * FROM user", function (error, result, fields) {
  console.log(result)
  console.log(fields)
})*/

//Setting up body parser
app.use(express.json())

//Importing routes
const auth = require("./routes/auth")

//Mounting routes
app.use("/api/v1/auth", auth)

//Handle unhandled routes
app.all("*", (req, res, next) => {
  res.status(404).json({
    success: false,
    message: "Page not found"
  })
})

const PORT = process.env.PORT
const server = app.listen(PORT, () => {
  console.log(`Server started on port ${PORT} in ${process.env.NODE_ENV} mode`)
})
