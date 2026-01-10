import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.webcrypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export default async function handler(req, res) {
  // ✅ Dynamic CORS
  const allowedOrigins = [
    'http://localhost:400',
    'https://www.sellytcishq.com',
    'https://www.stores.sellytcishq.com'

  ];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  // Handle preflight
  if (req.method === 'OPTIONS') return res.status(204).end();

  if (req.method !== 'POST') return res.status(405).json({ message: 'Method not allowed' });

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

    return res.status(200).json({ message: 'Password successfully reset' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Internal server error' });
  }
}
