const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const userSchema = new Schema(
  {
    name: {
      type: String,
      require: true,
    },
    email: {
      type: String,
      require: true,
      unique: true,
    },
    username: {
      type: String,
      require: true,
      unique: true,
    },
    password: {
      type: String,
      require: true,
    },
    phone: {
      type: String,
      require: false,
    },
    emailAuthenticated: {
      type: Boolean,
      require: true,
      default: false,
    },
  },
  { strict: false }
);

module.exports = mongoose.model("users", userSchema);