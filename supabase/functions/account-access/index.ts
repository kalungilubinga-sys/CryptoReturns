import { createClient, type SupabaseClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { corsHeaders, jsonResponse } from '../_shared/cors.ts';

// Existing Supabase credentials and protected profile roles are authoritative.
// Login and signup NEVER provision administrators, change passwords, or assign roles.
// Credential changes require a verified administrator role and either the current
// password or a fresh Supabase recovery code delivered to the existing email.
const normalizePhone = (value: string) => value.trim().replace(/[\s()\-]/g, '');
const validEmail = (value: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254;
const validPhone = (value: string) => /^\+[1-9]\d{6,14}$/.test(value);
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isConfiguredAdministrator(email: string | null | undefined): boolean {
  const configured = (Deno.env.get('CR_ADMIN_EMAIL') ?? '').trim().toLowerCase();
  return !!configured && configured === email?.trim().toLowerCase();
}
const phoneConflict = 'This phone number is already registered. To create a normal user account, use a different phone number. Administrators should sign in with their existing credentials to open the Admin Dashboard.';

type Identity = {
  user_id: string;
  email: string | null;
  profile_phone: string | null;
  account_role: string | null;
  banned: boolean;
  email_confirmed: boolean;
};

class AccessError extends Error {
  constructor(message: string, public status = 400, public code = 'ACCESS_ERROR') { super(message); }
}

async function lookup(admin: SupabaseClient, identity: string): Promise<Identity[]> {
  const { data, error } = await admin.rpc('cr_lookup_auth_identity', { p_identity: identity });
  if (error || !Array.isArray(data)) {
    throw new AccessError('Account validation is unavailable. Please retry or contact Admin.', 503, 'IDENTITY_LOOKUP_FAILED');
  }
  return data as Identity[];
}

async function verifiedAccess(admin: SupabaseClient, token: string) {
  // getUser validates the token with Supabase Auth; client metadata is not authorization.
  const { data, error } = await admin.auth.getUser(token);
  if (error || !data.user) throw new AccessError('Your session expired. Sign in again.', 401, 'SESSION_EXPIRED');
  const { data: profile, error: profileError } = await admin.from('profiles')
    .select('id,role,banned').eq('id', data.user.id).single();
  if (profileError || !profile) {
    throw new AccessError('Your account profile is unavailable. Contact Admin; no account was changed.', 409, 'PROFILE_UNAVAILABLE');
  }
  if (profile.banned) throw new AccessError('Your account has been banned. Contact Admin.', 403, 'ACCOUNT_BANNED');
  // A reserved administrator identity must fail closed if its stored role is wrong.
  // Never repair it by changing roles, credentials, or redirecting to a user workspace.
  if (isConfiguredAdministrator(data.user.email) && profile.role !== 'admin') {
    throw new AccessError('Administrator permissions could not be verified. Contact the project owner to review the existing account. No User Dashboard access was granted and no account was changed.', 403, 'ADMIN_ROLE_REQUIRED');
  }
  if (profile.role !== 'admin' && profile.role !== 'user') {
    throw new AccessError('Your account permissions are unavailable. Contact Admin.', 403, 'ROLE_UNAVAILABLE');
  }
  return {
    user_id: data.user.id,
    role: profile.role,
    // Administrator access never depends on the legacy password-setup flag.
    password_ready: profile.role === 'admin' || data.user.user_metadata?.password_ready !== false,
  };
}

async function clearSession(auth: SupabaseClient) {
  const { error } = await auth.auth.signOut({ scope: 'local' });
  if (error) console.error('account-access: rejected session cleanup failed');
}

async function login(admin: SupabaseClient, auth: SupabaseClient, body: Record<string, unknown>) {
  if (typeof body.identity !== 'string' || typeof body.password !== 'string') {
    throw new AccessError('Enter your email or international phone number and password.');
  }
  const identity = body.identity.trim(), password = body.password;
  if (!identity || identity.length > 254 || !password || password.length > 1024) {
    throw new AccessError('Enter your email or international phone number and password.');
  }
  let credentials: { email: string; password: string } | { phone: string; password: string };
  if (identity.includes('@')) {
    const email = identity.toLowerCase();
    if (!validEmail(email)) throw new AccessError('Enter a valid email address.');
    credentials = { email, password };
  } else {
    const phone = normalizePhone(identity);
    if (!validPhone(phone)) throw new AccessError('Use an international phone number beginning with + and country code.');
    const matches = await lookup(admin, phone);
    if (matches.length > 1) {
      throw new AccessError('This phone number has conflicting ownership records. Contact Admin; no account was changed.', 409, 'PHONE_OWNERSHIP_CONFLICT');
    }
    // Resolve email-verified phone logins privately; never return the account directory.
    credentials = matches[0]?.email ? { email: matches[0].email, password } : { phone, password };
  }
  const { data, error } = await auth.auth.signInWithPassword(credentials);
  if (error) {
    const banned = error.code === 'user_banned';
    throw new AccessError(
      banned ? 'Your account has been banned. Contact Admin.' : error.code === 'invalid_credentials' ? 'Incorrect email or phone number and password.' : error.message,
      error.status === 429 ? 429 : banned ? 403 : 400,
      banned ? 'ACCOUNT_BANNED' : error.code || 'LOGIN_FAILED',
    );
  }
  if (!data.user || !data.session) throw new AccessError('Supabase did not return a valid session.', 503);
  try {
    const access = await verifiedAccess(admin, data.session.access_token);
    if (access.user_id !== data.user.id) throw new AccessError('Account session validation failed.', 401);
    return {
      ...access,
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
    };
  } catch (error) {
    await clearSession(auth);
    throw error;
  }
}

async function requestSignupCode(admin: SupabaseClient, auth: SupabaseClient, body: Record<string, unknown>) {
  if (typeof body.email !== 'string' || !body.metadata || typeof body.metadata !== 'object' || Array.isArray(body.metadata)) {
    throw new AccessError('Enter your email address and account details.');
  }
  const email = body.email.trim().toLowerCase(), metadata = body.metadata as Record<string, unknown>;
  const name = typeof metadata.full_name === 'string' ? metadata.full_name.trim() : '';
  const phone = typeof metadata.phone === 'string' ? normalizePhone(metadata.phone) : '';
  const country = typeof metadata.country === 'string' ? metadata.country.toUpperCase() : 'UG';
  if (!validEmail(email)) throw new AccessError('Enter a valid email address to receive your verification code.');
  if (!name || name.length > 120) throw new AccessError('Enter your full name, up to 120 characters.');
  if (phone && !validPhone(phone)) throw new AccessError('Enter an international phone number beginning with + and country code, or leave the optional phone field blank.');
  if (!/^[A-Z]{2}$/.test(country)) throw new AccessError('Choose a valid country.');

  const [emailMatches, phoneMatches] = await Promise.all([
    lookup(admin, email), phone ? lookup(admin, phone) : Promise.resolve([] as Identity[]),
  ]);
  if (emailMatches.length > 1) throw new AccessError('This email address has conflicting account records. Contact Admin.', 409, 'EMAIL_CONFLICT');
  const existing = emailMatches[0];
  // Reject an administrator's number even when the supplied email is the same account.
  // This is a signup conflict, not a reason to change an account or its permissions.
  if (phoneMatches.some(owner => owner.user_id !== existing?.user_id || owner.account_role !== 'user') || phoneMatches.length > 1) {
    throw new AccessError(phoneConflict, 409, 'PHONE_ALREADY_REGISTERED');
  }
  if (existing?.account_role === 'admin' || isConfiguredAdministrator(email)) {
    throw new AccessError('This email address is already registered. Sign in with your existing administrator credentials to open the Admin Dashboard. Use a different email address and, if provided, a different phone number for a normal user account.', 409, 'EMAIL_ALREADY_REGISTERED');
  }
  if (existing && (existing.account_role !== 'user' || existing.banned)) {
    throw new AccessError('This email address is already registered. Use a different email address or contact Admin.', 409, 'EMAIL_ALREADY_REGISTERED');
  }
  if (existing?.email_confirmed) {
    throw new AccessError('This email address is already registered. Sign in to the existing account or use a different email address.', 409, 'EMAIL_ALREADY_REGISTERED');
  }
  if (existing && normalizePhone(existing.profile_phone || '') !== phone) {
    throw new AccessError('A pending account already uses this email with different contact details. Use its original details to resend the code, or use a different email address.', 409, 'PENDING_ACCOUNT_CONFLICT');
  }

  // Only unfinished normal-user signups may request another code for the same account.
  // Never overwrite existing account metadata, credentials, roles, or financial data.
  const options: { shouldCreateUser: boolean; data?: Record<string, unknown> } = { shouldCreateUser: !existing };
  if (!existing) {
    options.data = { full_name: name, phone, country, password_ready: false };
    if (typeof metadata.referrer === 'string' && uuid.test(metadata.referrer)) options.data.referrer = metadata.referrer;
  }
  const { error } = await auth.auth.signInWithOtp({ email, options });
  if (error) {
    // Database phone guards remain the final authority, including concurrent signups.
    if (phone) {
      const owners = await lookup(admin, phone);
      if (owners.some(owner => owner.user_id !== existing?.user_id)) {
        throw new AccessError(phoneConflict, 409, 'PHONE_ALREADY_REGISTERED');
      }
    }
    if (/profiles_unique_phone|phone number is already registered/i.test(error.message)) {
      throw new AccessError(phoneConflict, 409, 'PHONE_ALREADY_REGISTERED');
    }
    throw new AccessError(error.message, error.status === 429 ? 429 : 400, error.code || 'CODE_REQUEST_FAILED');
  }
  return { sent: true };
}

// Called only after password reauthentication or a fresh recovery-code check.
// Both paths use the same user-scoped update and preserve email confirmation.
async function updateAdministratorCredentials(
  admin: SupabaseClient, auth: SupabaseClient, userId: string,
  currentEmail: string, email: string, password: string,
) {
  const emailChanged = email !== currentEmail.toLowerCase();
  if (emailChanged) {
    const owners = await lookup(admin, email);
    if (owners.some(owner => owner.user_id !== userId)) {
      throw new AccessError('This email address already belongs to another account. Use a different email address; accounts cannot be merged.', 409, 'EMAIL_ALREADY_REGISTERED');
    }
  }
  // Never use the service-role Auth API to overwrite credentials or confirm email.
  // The existing UUID, protected role, phone ownership and financial records remain.
  const { data: updated, error: updateError } = await auth.auth.updateUser({
    password, ...(emailChanged ? { email } : {}),
  });
  if (updateError) throw new AccessError(updateError.message, updateError.status === 429 ? 429 : 400, updateError.code || 'CREDENTIAL_UPDATE_FAILED');
  if (!updated.user || updated.user.id !== userId) {
    throw new AccessError('Supabase did not confirm the update. Check your email and sign in again before retrying.', 503, 'UPDATE_UNCONFIRMED');
  }
  let warning = '';
  const { error: signOutError } = await auth.auth.signOut({ scope: 'others' });
  if (signOutError) warning = 'Other sessions could not be signed out. Review active sessions in Supabase.';
  const { data: sessionData, error: sessionError } = await auth.auth.getSession();
  const session = sessionData.session;
  return {
    user_id: userId,
    role: 'admin',
    password_updated: true,
    email_confirmation_pending: emailChanged && updated.user.email?.toLowerCase() !== email,
    email_change_requested: emailChanged,
    warning,
    // Already-issued access tokens may remain valid until their expiry.
    ...(sessionError || !session ? {} : { access_token: session.access_token, refresh_token: session.refresh_token }),
  };
}

async function changeAdministratorLogin(admin: SupabaseClient, auth: SupabaseClient, token: string, body: Record<string, unknown>) {
  const access = await verifiedAccess(admin, token);
  if (access.role !== 'admin') throw new AccessError('Administrator access required.', 403, 'ADMIN_REQUIRED');
  if (typeof body.current_password !== 'string' || typeof body.new_password !== 'string' || typeof body.email !== 'string') {
    throw new AccessError('Enter your current password, new email address, and new password.');
  }
  const email = body.email.trim().toLowerCase();
  if (!validEmail(email)) throw new AccessError('Enter a valid new email address.');
  if (!body.current_password || body.current_password.length > 1024) throw new AccessError('Enter your current password.');
  if (body.new_password.length < 8 || body.new_password.length > 1024) throw new AccessError('Your new password must contain between 8 and 1,024 characters.');
  if (body.current_password === body.new_password) throw new AccessError('Choose a new password different from your current password.');

  const { data: current, error: currentError } = await admin.auth.getUser(token);
  if (currentError || !current.user || current.user.id !== access.user_id) {
    throw new AccessError('Your session expired. Sign in again.', 401, 'SESSION_EXPIRED');
  }
  const currentEmail = current.user.email;
  if (!currentEmail) throw new AccessError('This administrator account has no email login. Contact the project owner; no credentials were changed.', 409, 'EMAIL_LOGIN_REQUIRED');
  const { data: reauthenticated, error: reauthError } = await auth.auth.signInWithPassword({
    email: currentEmail, password: body.current_password,
  });
  if (reauthError || !reauthenticated.session || !reauthenticated.user) {
    throw new AccessError(reauthError?.status === 429 ? 'Too many attempts. Wait before retrying.' : 'Your current password could not be verified. No credentials were changed.', reauthError?.status === 429 ? 429 : 403, 'REAUTHENTICATION_FAILED');
  }
  try {
    if (reauthenticated.user.id !== access.user_id) throw new AccessError('Account verification failed. No credentials were changed.', 403);
    const checked = await verifiedAccess(admin, reauthenticated.session.access_token);
    if (checked.role !== 'admin' || checked.user_id !== access.user_id) throw new AccessError('Administrator permissions could not be verified. No credentials were changed.', 403);
    return await updateAdministratorCredentials(admin, auth, access.user_id, currentEmail, email, body.new_password);
  } catch (error) {
    await clearSession(auth);
    throw error;
  }
}

async function recoverAdministratorLogin(admin: SupabaseClient, auth: SupabaseClient, body: Record<string, unknown>) {
  if (typeof body.current_email !== 'string' || typeof body.code !== 'string' || typeof body.email !== 'string' || typeof body.new_password !== 'string') {
    throw new AccessError('Enter your previous email, its recovery code, your new email, and a new password.');
  }
  const currentEmail = body.current_email.trim().toLowerCase();
  const email = body.email.trim().toLowerCase(), code = body.code.trim();
  if (!validEmail(currentEmail) || !validEmail(email)) throw new AccessError('Enter valid previous and new email addresses.');
  if (!/^\d{4,10}$/.test(code)) throw new AccessError('Enter the numeric recovery code from your previous email inbox.');
  if (body.new_password.length < 8 || body.new_password.length > 1024) throw new AccessError('Your new password must contain between 8 and 1,024 characters.');

  // Knowing an email, a generic login session, or configured secrets is NOT proof.
  // Only a fresh Supabase recovery code sent to the existing email is accepted.
  const { data: recovered, error: recoveryError } = await auth.auth.verifyOtp({
    email: currentEmail, token: code, type: 'recovery',
  });
  if (recoveryError || !recovered.user || !recovered.session) {
    throw new AccessError(recoveryError?.status === 429 ? 'Too many attempts. Wait before requesting another recovery code.' : 'This recovery code is incorrect, expired, or already used. Request a new code and use the latest email.', recoveryError?.status === 429 ? 429 : 400, 'RECOVERY_CODE_INVALID');
  }
  try {
    if (recovered.user.email?.toLowerCase() !== currentEmail) throw new AccessError('Recovery account verification failed. No login details were changed.', 403, 'RECOVERY_ACCOUNT_MISMATCH');
    const checked = await verifiedAccess(admin, recovered.session.access_token);
    if (checked.role !== 'admin' || checked.user_id !== recovered.user.id) {
      throw new AccessError('This recovery flow is for an existing administrator only. Use Forgot password for a normal user account. No login details were changed.', 403, 'ADMIN_REQUIRED');
    }
    return await updateAdministratorCredentials(admin, auth, checked.user_id, currentEmail, email, body.new_password);
  } catch (error) {
    await clearSession(auth);
    // A successfully verified code is single-use, even if the subsequent update fails.
    if (error instanceof AccessError && error.code !== 'UPDATE_UNCONFIRMED') {
      throw new AccessError(`${error.message} Request a new recovery code before retrying.`, error.status, error.code);
    }
    throw error;
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return jsonResponse({ error: 'Method not allowed.' }, 405);
  try {
    const raw = await req.text();
    if (raw.length > 10000) return jsonResponse({ error: 'Request is too large.' }, 413);
    const body = JSON.parse(raw);
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new AccessError('Invalid request.');
    const url = Deno.env.get('SUPABASE_URL'), serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'), anonKey = Deno.env.get('SUPABASE_ANON_KEY');
    if (!url || !serviceKey || !anonKey) throw new AccessError('Server authentication configuration is unavailable. Contact the project owner.', 503);
    const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
    const action = body.action ?? 'login';
    if (action === 'session') {
      const token = req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '').trim();
      if (!token) throw new AccessError('Sign in to continue.', 401, 'SESSION_EXPIRED');
      return jsonResponse(await verifiedAccess(admin, token));
    }
    const auth = createClient(url, anonKey, { auth: { persistSession: false, autoRefreshToken: false } });
    if (action === 'change-admin-login') {
      const token = req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '').trim();
      if (!token) throw new AccessError('Sign in as an administrator to change your login details.', 401, 'SESSION_EXPIRED');
      return jsonResponse(await changeAdministratorLogin(admin, auth, token, body));
    }
    if (action === 'recover-admin-login') return jsonResponse(await recoverAdministratorLogin(admin, auth, body));
    if (action === 'signup') return jsonResponse(await requestSignupCode(admin, auth, body));
    if (action === 'login') return jsonResponse(await login(admin, auth, body));
    throw new AccessError('Unsupported account action.');
  } catch (error) {
    // Never log passwords, emails, tokens, request bodies, or environment values.
    console.error('account-access: request failed', error instanceof AccessError ? `HTTP ${error.status} ${error.code}` : 'Unexpected server error');
    const status = error instanceof AccessError ? error.status : error instanceof SyntaxError ? 400 : 500;
    return jsonResponse({
      error: error instanceof AccessError ? error.message : error instanceof SyntaxError ? 'Invalid request.' : 'Unable to complete account access. Please retry.',
      code: error instanceof AccessError ? error.code : 'REQUEST_FAILED',
    }, status);
  }
});
