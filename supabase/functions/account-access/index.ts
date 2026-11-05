import { createClient, type SupabaseClient, type User } from 'https://esm.sh/@supabase/supabase-js@2';
import { corsHeaders, jsonResponse } from '../_shared/cors.ts';

// Only this server-side function reads the configured administrator credentials.
// Neither secrets nor service-role keys are returned, stored in profile metadata, or logged.
const ADMIN_PHONE = '+256788417769';
const normalizePhone = (value: string) => value.trim().replace(/[\s()\-]/g, '');

class LoginError extends Error {
  constructor(message: string, public status = 400) { super(message); }
}

async function passwordsMatch(submitted: string, configured: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [left, right] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(submitted)),
    crypto.subtle.digest('SHA-256', encoder.encode(configured)),
  ]);
  const a = new Uint8Array(left), b = new Uint8Array(right);
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

// This directory lookup is called only after BOTH configured identity and password match.
async function findUserByEmail(admin: SupabaseClient, email: string): Promise<User | null> {
  for (let page = 1; ; page++) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 200 });
    if (error) throw new LoginError('Administrator account lookup is unavailable. Please retry.', 503);
    const user = data.users.find(candidate => candidate.email?.toLowerCase() === email);
    if (user) return user;
    if (data.users.length < 200) return null;
  }
}

async function clearSession(auth: SupabaseClient) {
  const { error } = await auth.auth.signOut({ scope: 'local' });
  if (error) console.error('account-access: temporary session cleanup failed');
}

async function configuredAdminLogin(admin: SupabaseClient, auth: SupabaseClient, email: string, password: string) {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8 || password.length > 1024) {
    throw new LoginError('Administrator credentials are not configured correctly. Contact the project owner.', 503);
  }

  // Never adopt an unrelated account just because it uses the administrator phone.
  const { data: phoneProfile, error: phoneError } = await admin.from('profiles')
    .select('id,role,banned').eq('phone', ADMIN_PHONE).maybeSingle();
  if (phoneError) throw new LoginError('Administrator profile lookup is unavailable. Please retry.', 503);
  let account: User | null = null;
  if (phoneProfile) {
    const { data, error } = await admin.auth.admin.getUserById(phoneProfile.id);
    if (error || !data.user) throw new LoginError('Administrator authentication account is unavailable. Contact the project owner.', 409);
    if (data.user.email?.toLowerCase() !== email) {
      throw new LoginError('The configured administrator identity conflicts with an existing account. Contact the project owner; no account was changed.', 409);
    }
    account = data.user;
  } else {
    account = await findUserByEmail(admin, email);
  }

  if (!account) {
    // A trusted workspace owner supplied these credentials through the secure key UI.
    // This creates a real administrator account; financial balances come from the SQL trigger.
    const { data, error } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name: 'Crypto Returns Admin', phone: ADMIN_PHONE, country: 'UG', password_ready: true },
    });
    if (error || !data.user) {
      throw new LoginError('Unable to create the configured administrator account. Check Supabase Auth settings and retry; an existing account will not be overwritten.', 409);
    }
    account = data.user;
  }

  const { data: profile, error: profileError } = await admin.from('profiles')
    .select('id,phone,role,banned').eq('id', account.id).maybeSingle();
  if (profileError || !profile) throw new LoginError('Administrator profile is missing. Check the account-creation database trigger.', 409);
  const bannedUntil = (account as User & { banned_until?: string }).banned_until;
  if (profile.banned || (bannedUntil && new Date(bannedUntil).getTime() > Date.now())) {
    throw new LoginError('Your account has been banned. Contact Admin.', 403);
  }
  if ((profile.phone && normalizePhone(profile.phone) !== ADMIN_PHONE) ||
      (account.phone && normalizePhone(account.phone) !== ADMIN_PHONE)) {
    throw new LoginError('The configured administrator identity conflicts with an existing phone number. Contact the project owner; no account was changed.', 409);
  }
  const { data: balance, error: balanceError } = await admin.from('balances')
    .select('user_id').eq('user_id', account.id).maybeSingle();
  if (balanceError || !balance) throw new LoginError('Administrator balance record is missing. Check the account-creation database trigger.', 409);

  if (account.user_metadata?.password_ready === false) {
    const { error } = await admin.auth.admin.updateUserById(account.id, {
      user_metadata: { ...account.user_metadata, password_ready: true },
    });
    if (error) throw new LoginError('Administrator account setup could not be completed. Please retry.', 503);
  }

  let result = await auth.auth.signInWithPassword({ email, password });
  if (result.error && ['invalid_credentials', 'email_not_confirmed'].includes(result.error.code ?? '')) {
    // Only an exact match to the SERVER secrets authorizes setup or credential rotation.
    // Ordinary user passwords never enter this branch and cannot change roles.
    const { error: updateError } = await admin.auth.admin.updateUserById(account.id, {
      password,
      email_confirm: true,
      user_metadata: { ...account.user_metadata, password_ready: true },
    });
    if (updateError) throw new LoginError('The configured administrator password could not be applied. Check Supabase password requirements.', 409);
    result = await auth.auth.signInWithPassword({ email, password });
  }
  if (result.error) {
    throw new LoginError(result.error.code === 'user_banned' ? 'Your account has been banned. Contact Admin.' : result.error.message, result.error.status === 429 ? 429 : 400);
  }
  if (!result.data.user || !result.data.session || result.data.user.id !== account.id) {
    await clearSession(auth);
    throw new LoginError('Supabase did not return the expected administrator session.', 503);
  }

  // Privileges are stored only in the protected database role column, never signup metadata.
  const { data: updated, error: roleError } = await admin.from('profiles')
    .update({ role: 'admin', phone: ADMIN_PHONE }).eq('id', account.id).eq('banned', false).select('id').maybeSingle();
  if (roleError || !updated) {
    await clearSession(auth);
    throw new LoginError('Administrator access could not be assigned. Contact the project owner.', 409);
  }
  return result.data;
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return jsonResponse({ error: 'Method not allowed.' }, 405);
  try {
    const raw = await req.text();
    if (raw.length > 10000) return jsonResponse({ error: 'Request is too large.' }, 413);
    const body = JSON.parse(raw);
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new LoginError('Invalid request.');
    const identity = String(body.identity ?? '').trim();
    const password = String(body.password ?? '');
    if (!identity || identity.length > 254 || !password || password.length > 1024) {
      throw new LoginError('Enter your email or international phone number and password.');
    }
    const url = Deno.env.get('SUPABASE_URL');
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
    const anonKey = Deno.env.get('SUPABASE_ANON_KEY');
    if (!url || !serviceKey || !anonKey) throw new LoginError('Server authentication configuration is unavailable. Contact the project owner.', 503);
    const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
    const auth = createClient(url, anonKey, { auth: { persistSession: false, autoRefreshToken: false } });
    const adminEmail = (Deno.env.get('CR_ADMIN_EMAIL') ?? '').trim().toLowerCase();
    const adminPassword = Deno.env.get('CR_ADMIN_PASSWORD') ?? '';
    const emailIdentity = identity.includes('@') ? identity.toLowerCase() : '';
    const phoneIdentity = emailIdentity ? '' : normalizePhone(identity);
    const configuredIdentity = phoneIdentity === ADMIN_PHONE || (!!adminEmail && emailIdentity === adminEmail);

    if (configuredIdentity && adminEmail && adminPassword && await passwordsMatch(password, adminPassword)) {
      const data = await configuredAdminLogin(admin, auth, adminEmail, adminPassword);
      return jsonResponse({ access_token: data.session!.access_token, refresh_token: data.session!.refresh_token });
    }

    let credentials: { email: string; password: string } | { phone: string; password: string };
    if (emailIdentity) {
      credentials = { email: emailIdentity, password };
    } else {
      if (!/^\+[1-9]\d{6,14}$/.test(phoneIdentity)) throw new LoginError('Use an international phone number beginning with + and country code.');
      // Email-verified users may sign in with their profile phone; their email stays private.
      const { data: profile, error: lookupError } = await admin.from('profiles').select('id').eq('phone', phoneIdentity).maybeSingle();
      if (lookupError) throw new LoginError('Account lookup failed. Please try again.', 503);
      credentials = { phone: phoneIdentity, password };
      if (profile) {
        const { data, error } = await admin.auth.admin.getUserById(profile.id);
        if (error) throw new LoginError('Account lookup failed. Please try again.', 503);
        if (data.user?.email) credentials = { email: data.user.email, password };
        else if (data.user?.phone) credentials = { phone: data.user.phone, password };
      }
    }
    const { data, error } = await auth.auth.signInWithPassword(credentials);
    if (error) {
      return jsonResponse({ error: error.code === 'user_banned' ? 'Your account has been banned. Contact Admin.' : error.message }, error.status === 429 ? 429 : 400);
    }
    if (!data.user || !data.session) throw new LoginError('Supabase did not return a valid session.', 503);
    const { data: profile, error: profileError } = await admin.from('profiles').select('banned').eq('id', data.user.id).single();
    if (profileError || !profile) {
      await clearSession(auth);
      throw new LoginError('Your account profile is missing or unavailable. Contact Admin.', 409);
    }
    if (profile.banned) {
      await clearSession(auth);
      throw new LoginError('Your account has been banned. Contact Admin.', 403);
    }
    return jsonResponse({ access_token: data.session.access_token, refresh_token: data.session.refresh_token });
  } catch (error) {
    // Do not log request bodies, passwords, private emails, environment values, or auth tokens.
    console.error('account-access: request failed', error instanceof LoginError ? `HTTP ${error.status}` : 'Unexpected server error');
    const status = error instanceof LoginError ? error.status : error instanceof SyntaxError ? 400 : 500;
    return jsonResponse({ error: error instanceof LoginError ? error.message : error instanceof SyntaxError ? 'Invalid request.' : 'Unable to sign in. Check your connection and try again.' }, status);
  }
});
