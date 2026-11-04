import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { corsHeaders, jsonResponse } from '../_shared/cors.ts';

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return jsonResponse({ error: 'Method not allowed.' }, 405);
  try {
    const token = req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '');
    if (!token) return jsonResponse({ error: 'Sign in to view referrals.' }, 401);
    const admin = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { persistSession: false, autoRefreshToken: false } });
    const { data: authData, error: authError } = await admin.auth.getUser(token);
    if (authError || !authData.user) return jsonResponse({ error: 'Your session expired. Sign in again.' }, 401);
    const { data: profile, error: profileError } = await admin.from('profiles').select('banned').eq('id', authData.user.id).single();
    if (profileError) return jsonResponse({ error: 'Your profile is unavailable.' }, 409);
    if (profile.banned) return jsonResponse({ error: 'Your account has been banned. Contact Admin.' }, 403);
    const friends: unknown[] = [];
    for (let from = 0; ; from += 500) {
      const { data, error } = await admin.from('profiles').select('id,full_name,joined_at,referral_rewarded').eq('invited_by', authData.user.id).order('id').range(from, from + 499);
      if (error) return jsonResponse({ error: 'Unable to load referral records.' }, 500);
      friends.push(...data);
      if (data.length < 500) break;
    }
    // Only the caller's own invitations are returned; no global user directory.
    return jsonResponse({ friends });
  } catch (error) {
    console.error('referral-summary: failed', error instanceof Error ? error.message : 'Unknown error');
    return jsonResponse({ error: 'Unable to load referrals. Please try again.' }, 500);
  }
});
