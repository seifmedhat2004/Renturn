// sendEmail.js
require("dotenv").config(); // Load environment variables from .env
const sgMail = require("@sendgrid/mail");

// Set the API Key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Function to send password reset email
const sendPasswordResetEmail = async (email, resetCode) => {
  try {
    const msg = {
      to: email,
      from: `"Renturn System" <${process.env.SENDGRID_FROM_EMAIL}>`,
      subject: "Password Reset Code",
      text: `Hello,

You requested a password reset. Your reset code is: ${resetCode}

If you didn't request this, please ignore this email.

Thank you,
Renturn Team`,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.5;">
          <h2>Password Reset Request</h2>
          <p>Hello,</p>
          <p>You requested a password reset. Your reset code is:</p>
          <h3 style="color: #2E86C1;">${resetCode}</h3>
          <p>If you didn't request this, please ignore this email.</p>
          <hr/>
          <p style="font-size: 12px; color: #888;">
            Renturn System<br/>
            This is an automated message, please do not reply.
          </p>
        </div>
      `,
    };

    await sgMail.send(msg);
    console.log("Password reset email sent successfully");
    return true;
  } catch (error) {
    console.error(
      "Error sending password reset email:",
      error.response?.body || error.message,
    );
    throw new Error("Failed to send password reset email");
  }
};

module.exports = { sendPasswordResetEmail };
