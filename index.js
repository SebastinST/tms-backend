const express = require('express');
const dotenv = require("dotenv");

/* 
To-do
- Authenticate based on token (get username for functions)
- BcryptJS password
- CORS
*/

//Setting up config.env file variable
dotenv.config({ path: "./config/config.env" });

//Setting up database connection
const connection = require("./config/database");

// Inititalize the app and add middleware
const app = express();
app.use(express.json());

//Importing routes
const router = require("./router")

//Mounting routes
app.use("/", router)

/** App listening on port */
const PORT = process.env.PORT
app.listen(PORT, () => {
  console.log(`TMS at http://localhost:${PORT}`);
});