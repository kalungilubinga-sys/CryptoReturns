import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { corsHeaders, jsonResponse } from '../_shared/cors.ts';

// Shared, non-account market data. No fabricated prices or financial writes.
const coinIds = ['bitcoin', 'tron', 'binancecoin', 'ethereum', 'solana', 'hamster-kombat', 'pepe', 'ripple', 'dogecoin', 'sui'];
const freshFor = 60_000;
const maxQuoteAge = 15 * 60_000;
type Quote = { id: string; price: number; change_24h: number | null; updated_at: number };
type Snapshot = { quotes: Quote[]; fetchedAt: number };
let cached: Snapshot | null = null;
let pending: Promise<Snapshot> | null = null;
let retryAfter = 0;

function usableQuotes(snapshot: Snapshot): Quote[] {
  const now = Date.now();
  return snapshot.quotes.filter(quote => now - quote.updated_at * 1000 <= maxQuoteAge && quote.updated_at * 1000 <= now + 300_000);
}

async function fetchQuotes(): Promise<Snapshot> {
  const url = new URL('https://api.coingecko.com/api/v3/simple/price');
  url.searchParams.set('ids', coinIds.join(','));
  url.searchParams.set('vs_currencies', 'usd');
  url.searchParams.set('include_24hr_change', 'true');
  url.searchParams.set('include_last_updated_at', 'true');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12_000);
  try {
    const response = await fetch(url, { headers: { Accept: 'application/json' }, signal: controller.signal });
    if (!response.ok) throw new Error(`CoinGecko: HTTP ${response.status}`);
    const payload = await response.json();
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('CoinGecko: invalid response');
    const quotes: Quote[] = [];
    for (const id of coinIds) {
      const value = payload[id];
      if (!value || typeof value.usd !== 'number' || !Number.isFinite(value.usd) || value.usd <= 0 || typeof value.last_updated_at !== 'number' || !Number.isFinite(value.last_updated_at) || value.last_updated_at <= 0) continue;
      quotes.push({ id, price: value.usd, change_24h: typeof value.usd_24h_change === 'number' && Number.isFinite(value.usd_24h_change) ? value.usd_24h_change : null, updated_at: value.last_updated_at });
    }
    const snapshot = { quotes, fetchedAt: Date.now() };
    snapshot.quotes = usableQuotes(snapshot);
    if (!snapshot.quotes.length) throw new Error('CoinGecko: no recent prices available');
    cached = snapshot;
    retryAfter = 0;
    console.log('market-prices: refreshed', snapshot.quotes.length, 'quotes');
    return snapshot;
  } catch (error) {
    retryAfter = Date.now() + 90_000;
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return jsonResponse({ error: 'Method not allowed.' }, 405);
  try {
    // The gateway is disabled for publishable-key compatibility; validate every
    // caller here before serving cached or freshly retrieved market data.
    const token = req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '');
    if (!token) return jsonResponse({ error: 'Sign in to view market prices.' }, 401);
    const service = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { persistSession: false, autoRefreshToken: false } });
    const { data: auth, error: authError } = await service.auth.getUser(token);
    if (authError || !auth.user) return jsonResponse({ error: 'Your session expired. Sign in again.' }, 401);
    const { data: profile, error: profileError } = await service.from('profiles').select('banned').eq('id', auth.user.id).single();
    if (profileError || !profile) return jsonResponse({ error: 'Your account is unavailable.' }, 409);
    if (profile.banned) return jsonResponse({ error: 'Your account has been banned. Contact Admin.' }, 403);

    let snapshot = cached;
    let stale = false;
    if (!snapshot || Date.now() - snapshot.fetchedAt >= freshFor || !usableQuotes(snapshot).length) {
      try {
        if (Date.now() < retryAfter) throw new Error('CoinGecko: temporarily rate limited or unavailable');
        if (!pending) pending = fetchQuotes().finally(() => { pending = null; });
        snapshot = await pending;
      } catch (error) {
        console.error('market-prices: provider unavailable', error instanceof Error ? error.message : 'Unknown error');
        snapshot = cached;
        stale = true;
      }
    }
    if (!snapshot || !usableQuotes(snapshot).length) return jsonResponse({ error: 'Market prices are temporarily unavailable. Please retry shortly.' }, 503);
    return jsonResponse({ source: 'CoinGecko', quotes: usableQuotes(snapshot), fetched_at: new Date(snapshot.fetchedAt).toISOString(), stale });
  } catch (error) {
    console.error('market-prices: failed', error instanceof Error ? error.message : 'Unknown error');
    return jsonResponse({ error: 'Unable to load market prices. Please retry shortly.' }, 503);
  }
});
