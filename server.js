import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";
import cors from "cors";
import User from "./models/User.js"; // the schema file

const app = express();
const port = 3000; // Choose a port for your backend

app.use(express.json());
app.use(cors()); // Enable CORS for all origins (for development)

// MongoDB Connection (replace with your actual connection string)
const mongoUri = "mongodb://localhost:27017/signupDB";
mongoose.connect(mongoUri)
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.error("MongoDB connection error:", err));

// Nodemailer transporter (replace with your Gmail credentials)
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "yourgmail@gmail.com", // Replace with your Gmail address
        pass: "your-app-password"   // Replace with your App Password
    }
});

// Signup API endpoint
app.post("/signup", async (req, res) => {
    const { email, password, name } = req.body;

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ error: "User with this email already exists." });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);

        // Generate 6-digit OTP
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();

        // Save user in MongoDB
        const newUser = new User({
            name, // save name
            email,
            passwordHash,
            verificationCode,
            isVerified: false
        });
        await newUser.save();

        // Send Email
        await transporter.sendMail({
            from: "yourgmail@gmail.com", // Replace with your Gmail address
            to: email,
            subject: "Verify your account",
            html: `<p>Hello ${name},</p><p>Your verification code is: <b>${verificationCode}</b></p>` //add name and format email in html
        });

        res.status(201).json({ message: "Signup successful! Please check your email for the verification code." });

    } catch (err) {
        console.error("Signup error:", err);
        res.status(500).json({ error: "An internal server error occurred.", details: err.message });
    }
});

// Verify API endpoint
app.post("/verify", async (req, res) => {
    const { email, code } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found. Please sign up first." });
        }

        if (user.verificationCode === code) {
            user.isVerified = true;
            user.verificationCode = null; // clear code
            await user.save();
            res.json({ message: "Account verified successfully!" });
        } else {
            res.status(400).json({ message: "Invalid verification code" });
        }
    } catch (err) {
        console.error("Verification error:", err);
        res.status(500).json({ error: "An internal server error occurred during verification.", details: err.message });
    }
});

// Signin API endpoint
app.post("/signin", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ message: "Invalid email or password." });

        const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
        if (!isPasswordValid) return res.status(401).json({ message: "Invalid email or password." });

        if (!user.isVerified) {
            return res.status(403).json({ 
                message: "Account not verified. Please check your email for the OTP.",
                needsVerification: true 
            });
        }

        // Prepare user data to send back (excluding sensitive info)
        const userPayload = {
            name: user.name,
            email: user.email
        };

        res.json({ message: "Signin successful!", user: userPayload });

    } catch (err) {
        res.status(500).json({ error: "An internal server error occurred during sign-in.", details: err.message });
    }
});

app.listen(port, () => console.log(`Server running on port ${port}`));
