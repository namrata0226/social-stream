import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from 'jsonwebtoken';
import { User } from "../models/user.model.js";

export const verifyJWT = asyncHandler(async(req, _ , next)=>// Here res is not using so we are using _ in place of res
{
try {
    const token= req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ","")//For mobile app development
if(!token)
    throw new ApiError(401, "Unauthorized request")
const decodedToken= await jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

const user= await User.findById(decodedToken?._id).select(
    "-password -refreshToken"
  );
if(!user)
    throw new ApiError(401, "Invalid Access Token")
req.user=user; //adding user field in req object
next(); //passing middleware
} catch (error) {
    throw new ApiError(401, error?.message||"Unauthorized user")
}
})