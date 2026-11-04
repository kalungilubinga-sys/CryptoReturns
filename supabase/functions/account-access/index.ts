import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { corsHeaders, jsonResponse } from '../_shared/cors.ts';

// Passwords are passed only to Supabase Auth and are never stored or logged here.
Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return jsonResponse({ error: 'Method not allowed.' }, 405);
  try {
    const raw = await req.text();
    if (raw.length > 10000) return jsonResponse({ error: 'Request is too large.' }, 413);
    const body = JSON.parse(raw);
    const identity = String(body.identity ?? '').trim();
    const password = String(body.password ?? '');
    if (!identity || identity.length > 254 || !password || password.length > 1024) {
      return jsonResponse({ error: 'Enter your email or international phone number and password.' }, 400);
    }
    const url = Deno.env.get('SUPABASE_URL')!;
    const admin = createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { persistSession: false, autoRefreshToken: false } });
    const auth = createClient(url, Deno.env.get('SUPABASE_ANON_KEY')!, { auth: { persistSession: false, autoRefreshToken: false } });
    let credentials: { email: string; password: string } | { phone: string; password: string };
    if (identity.includes('@')) {
      credentials = { email: identity.toLowerCase(), password };
    } else {
      const phone = identity.replace(/[\s()\-]/g, '');
      if (!/^\+[1-9]\d{6,14}$/.test(phone)) return jsonResponse({ error: 'Use an international phone number beginning with + and country code.' }, 400);
      // Email-verified accounts may also log in using their profile phone number.
      // No account identity or email address is returned to the caller.
      const { data: profile, error: lookupError } = await admin.from('profiles').select('id').eq('phone', phone).maybeSingle();
      if (lookupError) throw new Error('Account lookup failed. Please try again.');
      credentials = { phone, password };
      if (profile) {
        const { data, error } = await admin.auth.admin.getUserById(profile.id);
        if (error) throw new Error('Account lookup failed. Please try again.');
        if (data.user?.phone) credentials = { phone: data.user.phone, password };
        else if (data.user?.email) credentials = { email: data.user.email, password };
      }
    }
    const { data, error } = await auth.auth.signInWithPassword(credentials);
    if (error) {
      const message = error.code === 'user_banned' ? 'Your account has been banned. Contact Admin.' : error.message;
      return jsonResponse({ error: message }, error.status === 429 ? 429 : 400);
    }
    if (!data.user || !data.session) throw new Error('Supabase did not return a valid session.');
    const { data: profile, error: profileError } = await admin.from('profiles').select('banned').eq('id', data.user.id).single();
    if (profileError) {
      await auth.auth.signOut();
      return jsonResponse({ error: 'Your account profile is missing or unavailable. Contact Admin.' }, 409);
    }
    if (profile.banned) {
      await auth.auth.signOut();
      return jsonResponse({ error: 'Your account has been banned. Contact Admin.' }, 403);
    }
    return jsonResponse({ access_token: data.session.access_token, refresh_token: data.session.refresh_token });
  } catch (error) {
    console.error('account-access: request failed', error instanceof Error ? error.message : 'Unknown error');
    return jsonResponse({ error: error instanceof SyntaxError ? 'Invalid request.' : 'Unable to sign in. Check your connection and try again.' }, 500);
  }
});
