import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// CORS headers
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': 'http://localhost:4000', // dev
  //'Access-Control-Allow-Origin': 'https://www.sellytcishq.com', // prod
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

// Helper: hash password
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.webcrypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS_HEADERS });
  if (req.method !== 'POST') return new Response(JSON.stringify({ message: 'Method not allowed' }), { status: 405, headers: CORS_HEADERS });

  const { token, newPassword } = await req.json();
  if (!token || !newPassword || newPassword.length < 6) {
    return new Response(JSON.stringify({ message: 'Invalid input' }), { status: 400, headers: CORS_HEADERS });
  }

  try {
    const { data: user, error } = await supabase
      .from('stores')
      .select('id, token_expiry')
      .eq('reset_token', token)
      .single();

    if (error || !user) return new Response(JSON.stringify({ message: 'Invalid or expired token' }), { status: 400, headers: CORS_HEADERS });
    if (new Date(user.token_expiry) < new Date()) return new Response(JSON.stringify({ message: 'Token expired' }), { status: 400, headers: CORS_HEADERS });

    const hashedPassword = await hashPassword(newPassword);
    const { error: updateError } = await supabase
      .from('stores')
      .update({ password: hashedPassword, reset_token: null, token_expiry: null })
      .eq('id', user.id);

    if (updateError) return new Response(JSON.stringify({ message: 'Failed to update password' }), { status: 500, headers: CORS_HEADERS });

    return new Response(JSON.stringify({ message: 'Password successfully reset' }), { status: 200, headers: CORS_HEADERS });

  } catch (err) {
    console.error(err);
    return new Response(JSON.stringify({ message: 'Internal server error' }), { status: 500, headers: CORS_HEADERS });
  }
}
