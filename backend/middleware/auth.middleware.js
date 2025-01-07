import jwt from 'jsonwebtoken';
import User from '../models/user.model.js';

export const protectRoute = async (req, res, next) => {
  try {
    const token = req.cookies["jwt-linkedin"];
    
    if (!token) {
      return res.status(401).json({ message: "You need to login first" });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // console.log(decoded);
    if (!decoded) {
      return res.status(401).json({ message: "You need to login first" });
    }

    
    const user = await User.findById(decoded.id).select("-password");

    console.log(user);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    req.user = user;


    next();
  } catch (error) {
    console.log("Error in protectRoute: ", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
}