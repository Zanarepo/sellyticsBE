// server.js
import express from 'express';
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import { Resend } from 'resend';
import dotenv from 'dotenv';

dotenv.config();
const app = express();
const port = process.env.PORT || 4000;

app.use(express.json());

// Supabase client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
// Resend client
const resend = new Resend(process.env.RESEND_API_KEY);

// ------------------
// CORS Middleware
// ------------------
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:400'); // add your frontend URL
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204); // handle preflight
  next();
});

// ------------------
// Helper Functions
// ------------------
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.webcrypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sendResetPasswordEmail(userEmail, resetToken) {
  const resetLink = `${process.env.BASE_URL}/reset-password?token=${resetToken}`;
  try {
    await resend.emails.send({
      from: 'Sellytics <no-reply@sellyticshq.com>',
      to: userEmail,
      subject: 'Reset Your Password',
      html: `<p>Dear Partner,</p>
             <p>Click <a href="${resetLink}">here</a> to reset your password.</p>`
    });
    console.log('✅ Reset email sent via Resend');
  } catch (err) {
    console.error('❌ Email send failed:', err);
  }
}

// ------------------
// Routes
// ------------------
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email required' });

  try {
    const { data: user, error } = await supabase
      .from('stores')
      .select('id, email_address')
      .eq('email_address', email.trim().toLowerCase())
      .single();

    if (error || !user) return res.status(404).json({ message: 'Store not found' });

    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 2 * 60 * 60 * 1000);

    await supabase
      .from('stores')
      .update({ reset_token: resetToken, token_expiry: tokenExpiry.toISOString() })
      .eq('id', user.id);

    await sendResetPasswordEmail(email, resetToken);
    res.status(200).json({ message: 'Reset link sent to email!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword || newPassword.length < 6)
    return res.status(400).json({ message: 'Invalid input' });

  try {
    const { data: user, error } = await supabase
      .from('stores')
      .select('id, token_expiry')
      .eq('reset_token', token)
      .single();

    if (error || !user) return res.status(400).json({ message: 'Invalid or expired token' });
    if (new Date(user.token_expiry) < new Date()) return res.status(400).json({ message: 'Token expired' });

    const hashedPassword = await hashPassword(newPassword);

    await supabase
      .from('stores')
      .update({ password: hashedPassword, reset_token: null, token_expiry: null })
      .eq('id', user.id);

    res.status(200).json({ message: 'Password successfully reset' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Test route
app.get('/', (req, res) => {
  res.send('Password reset server running!');
});

// Start server
app.listen(port, () => console.log(`🚀 Server running on http://localhost:${port}`));
