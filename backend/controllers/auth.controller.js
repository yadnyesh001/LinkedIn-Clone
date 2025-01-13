import User from '../models/user.model.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { sendWelcomeEmail } from '../emails/emailHandlers.js';

export const signup = async (req, res) => {
  try {
    const { name, username, email, password } = req.body;

    if (!name || !username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ message: 'Email already exists' });
    }
    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    if(password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await User.create({
      name,
      username,
      email, 
      password: hashedPassword,
    }); 

    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '3d' });

    res.cookie("jwt-linkedin", token, {
      httpOnly: true, // to disable accessing token via client side
      maxAge: 3 * 24 * 60 * 60 * 1000, // session cookie will expire after 3 days
      sameSite: 'strict',  // cookie will only be sent in same-site context
      secure: process.env.NODE_ENV === 'production', // cookie will only be sent in https
    });

    res.status(201).json({ message: 'User registered successfully' });

    const profileUrl = process.env.CLIENT_URL + "/profile/" + user.username

    try {
      await sendWelcomeEmail(user.email, user.name, profileUrl); 
    } catch (emailError) {
      console.log("Error sending welcome email: ", emailError);
    }

  } catch (error) {
    console.log("Error in signup: ", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
}

export const login = async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username});
    if(!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if(!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '3d' });
    await res.cookie("jwt-linkedin", token, {
      httpOnly: true,
      maxAge: 3 * 24 * 60 * 60 * 1000,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
    });

    res.json({ message: 'Logged in successfully' });

  } catch (error) {
    console.log("Error in login controller: ", error);
    res.status(500).json({ message: "Internal server error" });
  }
}

export const logout = async (req, res) => {
  res.clearCookie('jwt-linkedin');
  res.json({ message: 'Logged out successfully' });
}

export const getCurrentUser = async (req, res) => {
  try {
    res.json(req.user);
  } catch (error) {
    console.log("Error in getCurrentUser: ", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
}