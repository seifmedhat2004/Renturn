const asyncHandler = require("express-async-handler");
const User = require("../Models/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { sendPasswordResetEmail } = require("../services/emailService");

// Generate JWT Token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "30d",
  });
};

// Generate secure reset code
const generateResetCode = () => {
  return crypto.randomInt(100000, 999999).toString();
};

// @desc    Register new user
// @route   POST /api/v1/auth/register
// @access  Public
const registerUser = asyncHandler(async (req, res) => {
  const {
    firstname,
    lastname,
    email,
    password,
    confirmPassword,
    nationalID,
    adminSecret,
    phoneNumber,
  } = req.body;

  // Check if user exists by email
  const userExists = await User.findOne({ email });
  if (userExists) {
    res.status(400);
    throw new Error("User already exists");
  }

  // Check if passwords match
  if (password !== confirmPassword) {
    res.status(400);
    throw new Error("Passwords do not match");
  }

  // Validate national ID format (14 digits)
  if (!nationalID || nationalID.length !== 14 || !/^\d+$/.test(nationalID)) {
    res.status(400);
    throw new Error("National ID must be exactly 14 digits");
  }

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Hash national ID
  const hashedNationalID = await bcrypt.hash(nationalID, salt);
  // Determine user role based on admin secret
  let userRole = "user"; // Default role

  // Check if admin secret is provided and valid
  if (adminSecret) {
    if (!process.env.ADMIN_SECRET) {
      res.status(500);
      throw new Error("Admin secret not configured on server");
    }

    if (adminSecret === process.env.ADMIN_SECRET) {
      userRole = "admin";
    } else {
      res.status(403);
      throw new Error("Invalid admin secret");
    }
  }

  // Create user
  const user = await User.create({
    firstname,
    lastname,
    email,
    password: hashedPassword,
    confirmPassword: hashedPassword,
    nationalID: hashedNationalID,
    phoneNumber,
    role: userRole,
  });

  if (!user) {
    res.status(400);
    throw new Error("Invalid user data");
  }

  res.status(201).json({
    _id: user._id,
    firstname: user.firstname,
    lastname: user.lastname,
    email: user.email,
    role: user.role,
    token: generateToken(user._id),
  });
});

// @desc    Login user
// @route   POST /api/v1/auth/login
// @access  Public
const loginUser = asyncHandler(async (req, res) => {
  const { email, password, nationalID } = req.body;

  // Validate required fields
  if (!email || !password || !nationalID) {
    res.status(400);
    throw new Error("Email, password, and national ID are required");
  }

  // Validate national ID format
  if (nationalID.length !== 14 || !/^\d+$/.test(nationalID)) {
    res.status(400);
    throw new Error("National ID must be exactly 14 digits");
  }

  // Check if user exists
  const FindUser = await User.findOne({ email }).select("+password +nationalID");
  if (!FindUser) {
    res.status(401);
    throw new Error("Invalid credentials");
  }

  // Check password
  const IsPasswordMatch = await bcrypt.compare(password, user.password);
  if (!IsPasswordMatch) {
    res.status(401);
    throw new Error("Invalid credentials");
  }

  // Check national ID
  const isNationalIDMatch = await bcrypt.compare(nationalID, user.nationalID);
  if (!isNationalIDMatch) {
    res.status(401);
    throw new Error("Invalid credentials");
  }

  res.json({
    _id: user._id,
    firstname: user.firstname,
    lastname: user.lastname,
    email: user.email,
    role: user.role,
    token: generateToken(user._id),
  });
});

// @desc    Get current user profile
// @route   GET /api/v1/auth/me
// @access  Private
const getMe = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  res.json(user);
});

// @desc    Update user profile
// @route   PUT /api/v1/auth/updateprofile
// @access  Private
const updateProfile = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  user.firstname = req.body.firstname || user.firstname;
  user.lastname = req.body.lastname || user.lastname;
  user.email = req.body.email || user.email;

  // Update password if provided
  if (req.body.password) {
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(req.body.password, salt);
    user.confirmPassword = user.password;
  }

  // Update national ID if provided
  if (req.body.nationalID) {
    // Validate national ID format
    if (
      req.body.nationalID.length !== 14 ||
      !/^\d+$/.test(req.body.nationalID)
    ) {
      res.status(400);
      throw new Error("National ID must be exactly 14 digits");
    }
    const salt = await bcrypt.genSalt(10);
    user.nationalID = await bcrypt.hash(req.body.nationalID, salt);
  }

  const updatedUser = await user.save();

  res.json({
    _id: updatedUser._id,
    firstname: updatedUser.firstname,
    lastname: updatedUser.lastname,
    email: updatedUser.email,
    role: updatedUser.role,
    token: generateToken(updatedUser._id),
  });
});

// @desc    Logout user
// @route   POST /api/v1/auth/logout
// @access  Private
const logoutUser = asyncHandler(async (req, res) => {
  res.json({ message: "Logged out successfully" });
});

// @desc    Change password
// @route   PUT /api/v1/auth/changepassword
// @access  Private
const changePassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword, confirmNewPassword } = req.body;

  // Validate required fields
  if (!currentPassword || !newPassword || !confirmNewPassword) {
    res.status(400);
    throw new Error(
      "Current password, new password, and confirm password are required"
    );
  }

  // Check if new passwords match
  if (newPassword !== confirmNewPassword) {
    res.status(400);
    throw new Error("New passwords do not match");
  }

  // Get user with password
  const user = await User.findById(req.user._id).select("+password");
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  // Verify current password
  const isCurrentPasswordValid = await bcrypt.compare(
    currentPassword,
    user.password
  );
  if (!isCurrentPasswordValid) {
    res.status(401);
    throw new Error("Current password is incorrect");
  }

  // Hash new password
  const salt = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(newPassword, salt);
  user.confirmPassword = user.password;

  await user.save();

  res.json({ message: "Password changed successfully" });
});

// @desc    Get all users (admin only)
// @route   GET /api/v1/admin/users
// @access  Private/Admin
const getAllUsers = asyncHandler(async (req, res) => {
  const users = await User.find().select(
    "firstname lastname email  phoneNumber"
  );
  res.json({
    count: users.length,
    data: users,
  });
});

// @desc    Get user by ID (admin only)
// @route   GET /api/v1/admin/users/:id
// @access  Private/Admin
const getUserById = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id).select(
    "-password -nationalID"
  );

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  res.json(user);
});

// @desc    Delete user (admin only)
// @route   DELETE /api/v1/admin/users/:id
// @access  Private/Admin
const deleteUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  // Prevent admin from deleting themselves
  if (user._id.toString() === req.user._id.toString()) {
    res.status(400);
    throw new Error("Cannot delete your own account");
  }

  await User.findByIdAndDelete(req.params.id);

  res.json({ message: "User deleted successfully" });
});

// @desc    Forgot password
// @route   POST /api/v1/auth/forgotpassword
// @access  Public
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  // Validate required fields
  if (!email) {
    res.status(400);
    throw new Error("Email is required");
  }

  // Check if user exists
  const user = await User.findOne({ email });
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  // Generate secure 6-digit reset code
  const resetCode = generateResetCode();

  // Set expiration time (10 minutes from now)
  const resetCodeExpires = new Date(Date.now() + 10 * 60 * 1000);

  // Save reset code to user in database
  user.resetCode = resetCode;
  user.resetCodeExpires = resetCodeExpires;
  await user.save();

  // Send password reset email
  try {
    await sendPasswordResetEmail(email, resetCode);

    res.json({
      message: "Password reset code sent to your email",
      expiresIn: "10 minutes",
    });
  } catch (error) {
    // Remove the stored code if email fails
    user.resetCode = undefined;
    user.resetCodeExpires = undefined;
    await user.save();

    throw new Error(
      "Failed to send password reset email. Please try again later."
    );
  }
});

// @desc    Reset password
// @route   POST /api/v1/auth/resetpassword
// @access  Public
const resetPassword = asyncHandler(async (req, res) => {
  const { email, resetCode, newPassword, confirmNewPassword } = req.body;

  // Validate required fields
  if (!email || !resetCode || !newPassword || !confirmNewPassword) {
    res.status(400);
    throw new Error(
      "Email, reset code, new password, and confirm password are required"
    );
  }

  // Check if passwords match
  if (newPassword !== confirmNewPassword) {
    res.status(400);
    throw new Error("New passwords do not match");
  }

  // Find user with reset code
  const user = await User.findOne({ email }).select(
    "+resetCode +resetCodeExpires +password"
  );
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  // Check if reset code exists and is valid
  if (!user.resetCode || !user.resetCodeExpires) {
    res.status(400);
    throw new Error("No reset code found. Please request a new one.");
  }

  // Check if reset code matches
  if (user.resetCode !== resetCode) {
    res.status(400);
    throw new Error("Invalid reset code");
  }

  // Check if reset code has expired
  if (new Date() > user.resetCodeExpires) {
    // Clear expired reset code
    user.resetCode = undefined;
    user.resetCodeExpires = undefined;
    await user.save();

    res.status(400);
    throw new Error("Reset code has expired. Please request a new one.");
  }

  // Hash new password
  const salt = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(newPassword, salt);
  user.confirmPassword = user.password;

  // Clear reset code after successful password reset
  user.resetCode = undefined;
  user.resetCodeExpires = undefined;

  await user.save();

  res.json({ message: "Password reset successfully" });
});

module.exports = {
  registerUser,
  loginUser,
  getMe,
  updateProfile,
  logoutUser,
  changePassword,
  getAllUsers,
  getUserById,
  deleteUser,
  forgotPassword,
  resetPassword,
};
