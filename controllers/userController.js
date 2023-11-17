const { reset } = require("nodemon");
const User = require("../models/userModel");
const validator = require("validator");
//const bcrypt = require("bcrypt");
const sendMail = require("../utils/email").sendMail;
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");

// To create a jwt token we should split the process into 2 parts
// 1: Create a function that will sign a token
// To sign a token, we should provide 3 main factors:
// Factor 1: A unique field from the user: we choose always the id
// Factor 2: JWT_Secret
// Factor 3: JWT_EXPIRES_IN

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

// 2: Create a function that will send the token to the user
const createSendToken = (user, statusCode, res, msg) => {
  const token = signToken(user._id);

  res.status(statusCode).json({
    status: "success",
    token,
    data: {
      message: msg,
      user,
    },
  });
};


exports.signUp = async (req, res) => {
  try {
    
    let email = req.body.email;

    if (!validator.isEmail(email)) {
      return res.status(400).json({ message: "Invalid email." });
    }

    
    const checkEmail = await User.findOne({ email: req.body.email });
    if (checkEmail) {
      return res.status(400).json({ message: "Email already in use" });
    }

    
    let pass = req.body.password;
    let passConfirm = req.body.passwordConfirm;
    if (pass !== passConfirm) {
      return res
        .status(400)
        .json({ message: "Password and passwordConfirm are not the same." });
    }

    

    
    const newUser = await User.create({
      fullName: req.body.fullName,
      email: req.body.email,
      password: req.body.password,
    });

    let msg = "User created successfully.";
    createSendToken(newUser, 201, res, msg);

    
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
};

exports.login = async (req, res) => {
  try {
    
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return res.status(404).json({ message: "The user does not exist" });
    }


    if (!(await user.checkPassword(req.body.password, user.password))) {
      return res.status(401).json({ message: "Incorrect email or password" });
    }
    
    const msg = "You are logged in successfully !!";
    createSendToken(user, 200, res, msg);
  } catch (err) {
    console.log(err);
  }
};

exports.forgotPassword = async (req, res) => {
  try {
    
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res
        .status(404)
        .json({ message: "The user with the provided email does not exist." });
    }
    
    const resetToken = user.generatePsswordResetToken();
    await user.save({ validateBeforeSave: false });

    const url = `${req.protocol}://${req.get(
      "host"
    )}/api/auth/resetPassword/${resetToken}`;
    const msg = `Forgot your password? Reset it by visiting the following link: ${url}`;

    try {
      await sendMail({
        email: user.email,
        subject: "Your password reset token: (Valid for 10 min)",
        message: msg,
      });

      res.status(200).json({
        status: "success",
        message: "The reset link was delivered to your email successfully",
      });
    } catch (err) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });

      res.status(500).json({
        message:
          "An error occured while sending the email, please try again in a moment",
      });
    }
  } catch (err) {
    console.log(err);
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const hashedToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        message: "The token is invalid, or expired. Please request a new one",
      });
    }

    if (req.body.password.length < 8) {
      return res.status(400).json({ message: "Password length is too short" });
    }

    if (req.body.password !== req.body.passwordConfirm) {
      return res
        .status(400)
        .json({ message: "Password & Password Confirm are not the same" });
    }
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.passwordChangedAt = Date.now();

    await user.save();

    return res.status(200).json({ message: "Password changed successfully" });
  } catch (err) {
    console.log(err);
  }
};

exports.protect = async (req, res, next) => {
  try {
    
    let token;

    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
      return res
        .status(401)
        .json({ message: "You are not logged in. Please login to get access" });
    }


    let decoded;

    try {
      decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === "JsonWebTokenError") {
        return res.status(401).json({ message: "Invalid token, Login again" });
      } else if (error.name === "TokenExpiredError") {
        return res.status(401).json({
          message: " Your session token has expired !! Please login again",
        });
      }
    }
    
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return res
        .status(401)
        .json({ message: "The user belonging to this session deos not exist" });
    }
    
    if (currentUser.passwordChangedAfterTokenIssued(decoded.iat)) {
      return res
        .status(401)
        .json({
          message: "Your password has been changed!! Please login again",
        });
    }
    
    req.user = currentUser;
    next();
  } catch (err) {
    console.log(err);
  }
};
