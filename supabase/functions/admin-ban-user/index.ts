import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { corsHeaders, jsonResponse } from '../_shared/cors.ts';

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return jsonResponse({ error: 'Method not allowed.' }, 405);
  try {
    const token = req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '');
    if (!token) return jsonResponse({ error: 'Sign in as an administrator.' }, 401);
    const url = Deno.env.get('SUPABASE_URL')!;
    const admin = createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { persistSession: false, autoRefreshToken: false } });
    const { data: userData, error: authError } = await admin.auth.getUser(token);
    if (authError || !userData.user) return jsonResponse({ error: 'Your session expired. Sign in again.' }, 401);
    const { data: profile, error: profileError } = await admin.from('profiles').select('role,banned').eq('id', userData.user.id).single();
    if (profileError || profile.role !== 'admin' || profile.banned) return jsonResponse({ error: 'Administrator access required.' }, 403);
    const body = await req.json();
    if (typeof body.banned !== 'boolean' || !/^[0-9a-f-]{36}$/i.test(String(body.user_id ?? ''))) return jsonResponse({ error: 'Invalid user or ban state.' }, 400);
    const { data: target, error: targetError } = await admin.from('profiles').select('role').eq('id', body.user_id).single();
    if (targetError || target.role !== 'user') return jsonResponse({ error: 'User not found or administrator cannot be banned.' }, 400);
    const scoped = createClient(url, Deno.env.get('SUPABASE_ANON_KEY')!, {
      auth: { persistSession: false, autoRefreshToken: false },
      global: { headers: { Authorization: `Bearer ${token}` } },
    });
    if (body.banned) {
      // Database access and accrual stop first, even if the Auth service is unavailable.
      const { error: dbError } = await scoped.rpc('cr_set_banned', { p_user_id: body.user_id, p_banned: true });
      if (dbError) return jsonResponse({ error: dbError.message }, 400);
      const { error: banError } = await admin.auth.admin.updateUserById(body.user_id, { ban_duration: '876000h' });
      if (banError) {
        console.error('admin-ban-user: Auth lock failed', banError.message);
        return jsonResponse({ banned: true, warning: 'Database access and earnings are blocked, but the Auth lock failed. Retry Ban User from Supabase Auth.' });
      }
    } else {
      // Until both steps succeed, database policies continue to block access.
      const { error: authUnbanError } = await admin.auth.admin.updateUserById(body.user_id, { ban_duration: 'none' });
      if (authUnbanError) return jsonResponse({ error: `Supabase Auth: ${authUnbanError.message}` }, 400);
      const { error: dbError } = await scoped.rpc('cr_set_banned', { p_user_id: body.user_id, p_banned: false });
      if (dbError) {
        const { error: restoreError } = await admin.auth.admin.updateUserById(body.user_id, { ban_duration: '876000h' });
        if (restoreError) console.error('admin-ban-user: Auth relock failed', restoreError.message);
        return jsonResponse({ error: `Access remains blocked: ${dbError.message}` }, 400);
      }
    }
    return jsonResponse({ banned: body.banned });
  } catch (error) {
    console.error('admin-ban-user: failed', error instanceof Error ? error.message : 'Unknown error');
    return jsonResponse({ error: 'Unable to change account access. Please try again.' }, 500);
  }
});
