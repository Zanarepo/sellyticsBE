const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');
const express = require('express');
const cors = require('cors');
require('dotenv').config();
const crypto = require('crypto'); // Node's crypto module

const app = express();
const port = process.env.PORT || 4000;

app.use(express.json());
app.use(cors());

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Helper: Hash password using SHA-256
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.webcrypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Setup Nodemailer
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});



// Send Reset Email
async function sendResetPasswordEmail(userEmail, resetToken) {
  const resetLink = `${process.env.BASE_URL}/reset-password?token=${resetToken}`;
  const mailOptions = {
    from: `"Sellytics" <${process.env.EMAIL_USER}>`,
    to: userEmail,
    subject: 'Reset Your Password',
    text: `Hello Tracker! You requested a password reset.\n\nClick here to reset it:\n${resetLink}\n\nIf you did not request this, please ignore this email.`,
  };



  try {
    await transporter.sendMail(mailOptions);
    console.log('✅ Reset email sent');
  } catch (error) {
    console.error('❌ Email send failed:', error);
  }
}









// Forgot Password Route
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email || typeof email !== 'string') {
    return res.status(400).json({ message: 'Valid email is required' });
  }

  try {
    const { data: user, error } = await supabase
    .from('stores')
    .select('id, email_address')
    .eq('email_address', email.trim().toLowerCase())
    .single();
  

    if (error || !user) {
      return res.status(404).json({ message: 'Store not found' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 2 * 60 * 60 * 1000); // 2 hours

    const { error: updateError } = await supabase
      .from('stores')
      .update({
        reset_token: resetToken,
        token_expiry: tokenExpiry.toISOString(),
      })
      .eq('id', user.id);

    if (updateError) {
      console.error(updateError);
      return res.status(500).json({ message: 'Error setting reset token' });
    }

    await sendResetPasswordEmail(email, resetToken);
    res.status(200).json({ message: 'Reset link sent to email!' });
  } catch (err) {
    console.error('Error in forgot-password:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});















// Reset Password Route
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword || newPassword.length < 6) {
    return res.status(400).json({ message: 'Invalid input' });
  }

  try {
    const { data: user, error } = await supabase
      .from('stores')
      .select('id, token_expiry')
      .eq('reset_token', token)
      .single();

    if (error || !user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    if (new Date(user.token_expiry) < new Date()) {
      return res.status(400).json({ message: 'Token has expired' });
    }

    const hashedPassword = await hashPassword(newPassword);

    const { error: updateError } = await supabase
      .from('stores')
      .update({
        password: hashedPassword,
        reset_token: null,
        token_expiry: null,
      })
      .eq('id', user.id);

    if (updateError) {
      return res.status(500).json({ message: 'Failed to update password' });
    }

    res.status(200).json({ message: 'Password successfully reset' });
  } catch (err) {
    console.error('Reset error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Simple route to test server
app.get('/', (req, res) => {
  res.send('Password reset server running!');
});

app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});
