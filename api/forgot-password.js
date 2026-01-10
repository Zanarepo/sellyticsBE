import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import { Resend } from 'resend';
import dotenv from 'dotenv';

dotenv.config();

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const resend = new Resend(process.env.RESEND_API_KEY);

async function sendResetPasswordEmail(userEmail, resetToken) {
  const resetLink = `${process.env.BASE_URL}/reset-password?token=${resetToken}`;
  await resend.emails.send({
    from: 'Sellytics <no-reply@sellyticshq.com>',
    to: userEmail,
    subject: 'Reset Your Password',
    html: `<p>Dear Sellyrics Partner
           <p>Click <a href="${resetLink}">here</a> to reset your password.</p>`
  });
}

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:400'); // replace with frontend URL in prod
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(204).end(); // handle preflight

  if (req.method !== 'POST') return res.status(405).json({ message: 'Method not allowed' });

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

    return res.status(200).json({ message: 'Reset link sent to email!' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Internal server error' });
  }
}
