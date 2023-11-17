const express = require("express");
const app = express();
const DB = require("./database").connectDB;


const authRouter = require("./routes/authRoutes");
const userRouter = require("./routes/userRoutes");

DB();

app.use(express.json());
app.use("/api/auth", authRouter);
app.use("/api/users", userRouter);
//The signup path: http://localhost:3000/api/auth/signup

app.listen(process.env.PORT, () => {
  console.log(`Listening on port: ${process.env.PORT}`);
});
