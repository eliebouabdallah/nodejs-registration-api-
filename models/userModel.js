const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const crypto = require("crypto");

const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: [true, "Please enter your fullName"],
      trim: true,
    },
    email: {
      type: String,
      required: [true, "Please enter your email"],
      trim: true,
      unique: true,
      lowercase: true,
    },
    password: {
      type: String,
      trim: true,
      minLength: 8,
      maxLength: 30,
    },
    passwordConfirm: {
      type: String,
      trim: true,
      minLength: 8,
      maxLength: 30,
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
  },
  { timestamps: true }
);
// Automated function
userSchema.pre("save", async function (next) {
  try {
    if (!this.isModified("password")) {
      return next();
    }

    this.password = await bcrypt.hash(this.password, 12);
    this.passwordConfirm = undefined;
  } catch (err) {
    console.log(err);
  }
});

//This function will always return 1 value : True or False
userSchema.methods.checkPassword = async function (
  candidatePassword, // Coming from te frontend as a plain text
  userPassword // Coming from the database as a hashed value
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

//This function will create a random reset token
userSchema.methods.generatePsswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex"); //will be sent via email
  //saved in the database in a hashed way
  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  //10 min of validity
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  return resetToken;
};

//This function will check if the password was changed after issuing the jwt token
userSchema.methods.passwordChangedAfterTokenIssued = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const passwordChangeTime = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    return passwordChangeTime > JWTTimestamp;
  }

  return false;
};

module.exports = mongoose.model("User", userSchema);

//User --> users
