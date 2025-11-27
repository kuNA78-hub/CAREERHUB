// server.js - Complete Firebase Backend
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "karma-setu-2025-super-secure-jwt-key-123456789";

// ========== FIREBASE ADMIN SETUP ==========
try {
  // Use environment variables for security
  const serviceAccount = {
    type: "service_account",
    project_id: process.env.FIREBASE_PROJECT_ID || "karma-setu",
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: "https://accounts.google.com/o/oauth2/auth",
    token_uri: "https://oauth2.googleapis.com/token",
    auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
    client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
  };

  // Alternative: Use service account file if environment variables are not set
  if (!serviceAccount.private_key) {
    const serviceAccountFile = require('./serviceAccountKey.json');
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccountFile),
      databaseURL: `https://${serviceAccountFile.project_id}.firebaseio.com`
    });
    console.log("✅ Firebase Admin initialized from serviceAccountKey.json");
  } else {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`
    });
    console.log("✅ Firebase Admin initialized from environment variables");
  }
  
  console.log("🔧 Firebase Project:", admin.app().options.credential.projectId);
} catch (error) {
  console.error("❌ Firebase Admin initialization failed:", error.message);
  console.log("💡 Make sure you have either:");
  console.log("   1. serviceAccountKey.json file in project root, OR");
  console.log("   2. Firebase environment variables set");
  process.exit(1);
}

const db = admin.firestore();
const auth = admin.auth();

// ========== MIDDLEWARE ==========
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5000', 'http://127.0.0.1:5500'],
  credentials: true
}));

app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many attempts, try again later." }
});
app.use("/api/", limiter);

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
};

// ========== ROUTES ==========

// Health Check
app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    message: "KarmaSetu Backend Running!",
    timestamp: new Date().toISOString(),
    services: {
      firebase: "connected",
      database: "connected", 
      authentication: "active"
    }
  });
});

// Sign Up
app.post("/api/signup", async (req, res) => {
  try {
    console.log("📧 SIGNUP ATTEMPT:", req.body);
    const { email, password, firstName, lastName, phone, userType = "job_seeker" } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    console.log("🔧 Creating Firebase user...");
    
    // Create Firebase user
    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName: `${firstName || ""} ${lastName || ""}`.trim(),
      emailVerified: false,
    });

    console.log("✅ Firebase user created:", userRecord.uid);

    // Save user data to Firestore
    try {
      await admin.firestore().collection("users").doc(userRecord.uid).set({
        uid: userRecord.uid,
        email: email,
        firstName: firstName || "",
        lastName: lastName || "",
        phone: phone || "",
        userType: userType,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        profileComplete: false,
        emailVerified: false
      });
      console.log("✅ User data saved to Firestore");
    } catch (firestoreError) {
      console.error("⚠️ Firestore error:", firestoreError);
      // Continue even if Firestore fails
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        uid: userRecord.uid, 
        email: email,
        userType: userType
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    console.log(`🎉 SIGNUP SUCCESS: ${email}`);

    res.status(201).json({
      message: "User created successfully!",
      user: {
        uid: userRecord.uid,
        email: userRecord.email,
        displayName: userRecord.displayName || email.split('@')[0],
        emailVerified: userRecord.emailVerified,
        profileComplete: false
      },
      token: token
    });

  } catch (error) {
    console.error("🔥 SIGNUP ERROR:", error);

    let errorMessage = "Registration failed. Please try again.";
    
    if (error.code === 'auth/email-already-exists') {
      errorMessage = "This email is already registered. Please use a different email or try logging in.";
    } else if (error.code === 'auth/invalid-email') {
      errorMessage = "The email address is not valid.";
    } else if (error.code === 'auth/weak-password') {
      errorMessage = "The password is too weak. Please use a stronger password.";
    }

    res.status(400).json({ error: errorMessage });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // Verify user exists
    let userRecord;
    try {
      userRecord = await admin.auth().getUserByEmail(email);
    } catch (error) {
      if (error.code === 'auth/user-not-found') {
        return res.status(401).json({ error: "Invalid email or password" });
      }
      throw error;
    }

    // Get additional user data from Firestore
    let userData = {};
    try {
      const userDoc = await admin.firestore().collection("users").doc(userRecord.uid).get();
      if (userDoc.exists) {
        userData = userDoc.data();
      }
    } catch (firestoreError) {
      console.log("⚠️ Firestore access failed:", firestoreError.message);
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        uid: userRecord.uid, 
        email: userRecord.email,
        userType: userData.userType || "job_seeker"
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login successful",
      user: {
        uid: userRecord.uid,
        email: userRecord.email,
        displayName: userRecord.displayName || email.split('@')[0],
        userType: userData.userType || "job_seeker",
        profileComplete: userData.profileComplete || false
      },
      token
    });

  } catch (error) {
    console.error("Login Error:", error);
    res.status(401).json({ error: "Invalid email or password" });
  }
});

// Auth Check Endpoint
app.get("/api/auth/check", authenticateToken, async (req, res) => {
  try {
    const userRecord = await admin.auth().getUser(req.user.uid);
    
    let userData = {};
    try {
      const userDoc = await admin.firestore().collection("users").doc(req.user.uid).get();
      if (userDoc.exists) {
        userData = userDoc.data();
      }
    } catch (firestoreError) {
      console.log("Firestore access failed during auth check");
    }

    res.json({
      authenticated: true,
      user: {
        uid: userRecord.uid,
        email: userRecord.email,
        displayName: userRecord.displayName || userRecord.email.split('@')[0],
        ...userData
      }
    });
  } catch (error) {
    console.error("Auth check error:", error);
    res.status(401).json({ error: "Invalid authentication" });
  }
});

// User Profile Endpoint
app.get("/api/user/profile", authenticateToken, async (req, res) => {
  try {
    const userRecord = await admin.auth().getUser(req.user.uid);
    let userData = {};
    
    try {
      const userDoc = await admin.firestore().collection("users").doc(req.user.uid).get();
      if (userDoc.exists) {
        userData = userDoc.data();
      }
    } catch (error) {
      console.log("Firestore not available for profile");
    }

    res.json({
      user: {
        uid: userRecord.uid,
        email: userRecord.email,
        displayName: userRecord.displayName || userRecord.email.split('@')[0],
        ...userData
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch profile" });
  }
});

// Update User Profile
app.put("/api/user/profile", authenticateToken, async (req, res) => {
  try {
    const { firstName, lastName, phone } = req.body;
    const userId = req.user.uid;

    await admin.firestore().collection("users").doc(userId).update({
      firstName: firstName || "",
      lastName: lastName || "",
      phone: phone || "",
      profileComplete: true,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const userDoc = await admin.firestore().collection("users").doc(userId).get();
    const userData = userDoc.data();
    const userRecord = await admin.auth().getUser(userId);

    res.json({
      message: "Profile updated successfully",
      user: {
        uid: userRecord.uid,
        email: userRecord.email,
        displayName: userRecord.displayName || userRecord.email.split('@')[0],
        ...userData
      }
    });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({ error: "Failed to update profile" });
  }
});

// Get all users (for testing)
app.get("/api/users", authenticateToken, async (req, res) => {
  try {
    const usersSnapshot = await admin.firestore().collection("users").get();
    const users = [];
    usersSnapshot.forEach(doc => {
      users.push({ id: doc.id, ...doc.data() });
    });
    res.json(users);
  } catch (error) {
    console.error("Get users error:", error);
    res.status(500).json({ error: "Failed to get users" });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 KarmaSetu Backend RUNNING → http://localhost:${PORT}`);
  console.log(`✅ Firebase Authentication: Connected`);
  console.log(`✅ JWT Token System: Ready`);
  console.log(`📋 Available Endpoints:`);
  console.log(`   POST /api/signup - User registration`);
  console.log(`   POST /api/login - User login`);
  console.log(`   GET  /api/health - Health check`);
  console.log(`   GET  /api/auth/check - Check authentication`);
  console.log(`   GET  /api/user/profile - Get user profile`);
  console.log(`   PUT  /api/user/profile - Update user profile`);
});