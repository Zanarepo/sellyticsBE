import { createClient } from '@supabase/supabase-js';
import { Resend } from 'resend';
import crypto from 'crypto';

// Init Supabase + Resend
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const resend = new Resend(process.env.RESEND_API_KEY);

// CORS headers
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': 'http://localhost:4000', // dev
  //'Access-Control-Allow-Origin': 'https://www.sellytcishq.com', // prod
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

// Helper: send reset email
async function sendResetPasswordEmail(email, token) {
  const resetLink = `${process.env.BASE_URL}/reset-password?token=${token}`;
  await resend.emails.send({
    from: 'Sellytics <no-reply@sellyticshq.com>',
    to: email,
    subject: 'Reset Your Password',
    html: `
      <p>Dear Esteemed Partner!</p>
      <p>You requested a password reset.</p>
      <p><a href="${resetLink}">Click here to reset it</a></p>
      <p>If you did not request this, please ignore this email.</p>
    `
  });
}

export default async function handler(req, res) {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: CORS_HEADERS });
  }

  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ message: 'Method not allowed' }), {
      status: 405,
      headers: CORS_HEADERS
    });
  }

  const { email } = await req.json();
  if (!email || typeof email !== 'string') {
    return new Response(JSON.stringify({ message: 'Valid email required' }), { status: 400, headers: CORS_HEADERS });
  }

  try {
    const { data: user, error } = await supabase
      .from('stores')
      .select('id, email_address')
      .eq('email_address', email.trim().toLowerCase())
      .single();

    if (error || !user) {
      return new Response(JSON.stringify({ message: 'Store not found' }), { status: 404, headers: CORS_HEADERS });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 2 * 60 * 60 * 1000);

    const { error: updateError } = await supabase
      .from('stores')
      .update({ reset_token: resetToken, token_expiry: tokenExpiry.toISOString() })
      .eq('id', user.id);

    if (updateError) {
      return new Response(JSON.stringify({ message: 'Error setting reset token' }), { status: 500, headers: CORS_HEADERS });
    }

    await sendResetPasswordEmail(email, resetToken);
    return new Response(JSON.stringify({ message: 'Reset link sent!' }), { status: 200, headers: CORS_HEADERS });

  } catch (err) {
    console.error(err);
    return new Response(JSON.stringify({ message: 'Internal server error' }), { status: 500, headers: CORS_HEADERS });
  }
}
