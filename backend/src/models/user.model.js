import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { config } from "../config.js";

export const assetSchema = new Schema(
  { url: String, public_id: String, provider: { type: String, enum: ["local", "cloudinary", "external"] } },
  { _id: false }
);

const userSchema = new Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^[a-z0-9_.]{3,30}$/, "Username must be 3-30 letters, numbers, _ or ."],
    },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    fullName: { type: String, required: true, trim: true, maxlength: 60 },
    bio: { type: String, default: "", maxlength: 1000 },
    avatar: { type: assetSchema, default: null },
    coverImage: { type: assetSchema, default: null },
    myList: [{ type: Schema.Types.ObjectId, ref: "Video" }],
    password: { type: String, required: true, minlength: 6 },
    refreshToken: String,
  },
  { timestamps: true }
);

userSchema.pre("save", async function () {
  if (this.isModified("password")) this.password = await bcrypt.hash(this.password, 10);
});

userSchema.methods.isPasswordCorrect = function (password) {
  return bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = function () {
  return jwt.sign({ _id: this._id, username: this.username }, config.accessSecret, {
    expiresIn: config.accessExpiry,
  });
};

userSchema.methods.generateRefreshToken = function () {
  return jwt.sign({ _id: this._id }, config.refreshSecret, { expiresIn: config.refreshExpiry });
};

userSchema.methods.toPublic = function () {
  const { password, refreshToken, __v, ...rest } = this.toObject();
  return rest;
};

export const User = mongoose.model("User", userSchema);
