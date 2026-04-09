'use strict';
require('dotenv').config();

const express    = require('express');
const session    = require('express-session');
const bcrypt     = require('bcryptjs');
const rateLimit  = require('express-rate-limit');
const path       = require('path');
const fs         = require('fs');
const crypto     = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const helmet           = require('helmet');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Banned username words ────────────────────────────────────────────────────
const BANNED_USERNAME_WORDS = [
  'penis', 'dick', 'cock', 'pussy', 'vagina', 'cunt', 'asshole',
  'fuck', 'shit', 'bitch', 'whore', 'slut', 'nigger', 'nigga',
  'fag', 'faggot', 'retard', 'rape', 'cum', 'semen', 'dildo',
  'porn', 'hentai', 'anal', 'anus', 'tits', 'boobs', 'blowjob',
  'handjob', 'masturbat', 'orgasm', 'erection', 'ejaculat',
  'clitoris', 'scrotum', 'testicle', 'butthole', 'jizz', 'wank',
  'prick', 'twat', 'ballsack', 'nutsack', 'jackoff', 'jerkoff',
  'sexe', 'sexy', 'phallus', 'fetish', 'bondage', 'milf',
  'negro', 'spic', 'chink', 'kike', 'gook', 'wetback',
];
const LEET_MAP = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i' };
function normalizeLeet(str) {
  return str.toLowerCase().replace(/[013457@$!8]/g, c => LEET_MAP[c] || c);
}
function containsBannedWord(username) {
  const lower = username.toLowerCase();
  const normalized = normalizeLeet(username);
  // check both raw lowercase and leet-normalized version
  return BANNED_USERNAME_WORDS.some(w => lower.includes(w) || normalized.includes(w));
}

// ── Supabase ──────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY,
  { auth: { persistSession: false } }
);

// ── Session secret ────────────────────────────────────────────────────────────
const DATA_DIR    = path.join(__dirname, 'data');
const SECRET_FILE = path.join(DATA_DIR, 'secret.key');
const ADMIN_PANEL_FILE = path.join(__dirname, 'private', 'admin.html');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function getOrCreateSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  try { return fs.readFileSync(SECRET_FILE, 'utf8').trim(); } catch {}
  const s = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SECRET_FILE, s, { mode: 0o600 });
  return s;
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'", "'unsafe-hashes'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc:    ["'self'"],
      mediaSrc:   ["'self'"],
      objectSrc:  ["'none'"],
      frameSrc:   ["'none'"],
    },
  },
}));
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/assets', express.static(path.join(__dirname, 'assets')));
app.set('trust proxy', 1);
// ── Custom Supabase session store with in-memory cache ────────────────────────
class SupabaseStore extends session.Store {
  constructor() {
    super();
    this._mem = new Map();
    this._touchWriteAt = new Map();
  }

  _mc(sid) {
    const e = this._mem.get(sid);
    if (e && e.exp > Date.now()) return e.sess;
    this._mem.delete(sid);
    return null;
  }

  async get(sid, cb) {
    const cached = this._mc(sid);
    if (cached) return cb(null, cached);
    try {
      const { data } = await supabase.from('session').select('sess,expire').eq('sid', sid).maybeSingle();
      if (!data) return cb(null, null);
      if (new Date(data.expire) < new Date()) { this.destroy(sid, () => {}); return cb(null, null); }
      this._mem.set(sid, { sess: data.sess, exp: Date.now() + 300_000 });
      cb(null, data.sess);
    } catch(e) { cb(e); }
  }
  async set(sid, sess, cb) {
    try {
      const expire = sess.cookie?.expires || new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
      await supabase.from('session').upsert({ sid, sess, expire: new Date(expire).toISOString() }, { onConflict: 'sid' });
      this._mem.set(sid, { sess, exp: Date.now() + 300_000 });
      cb(null);
    } catch(e) { cb(e); }
  }
  async destroy(sid, cb) {
    this._mem.delete(sid);
    try { await supabase.from('session').delete().eq('sid', sid); cb(null); } catch(e) { cb(e); }
  }
  async touch(sid, sess, cb) {
    this._mem.set(sid, { sess, exp: Date.now() + 300_000 });
    const now = Date.now();
    const lastWrite = this._touchWriteAt.get(sid) || 0;
    if (now - lastWrite < 15 * 60 * 1000) return cb(null);
    this._touchWriteAt.set(sid, now);
    const expire = sess.cookie?.expires || new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    supabase.from('session').update({ expire: new Date(expire).toISOString() }).eq('sid', sid).then(() => {}, () => {});
    cb(null);
  }
}

app.use(session({
  store: new SupabaseStore(),
  secret: getOrCreateSecret(),
  resave: false,
  saveUninitialized: false,
  rolling: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 365 * 24 * 60 * 60 * 1000,
  },
}));

const globalLimiter = rateLimit({ windowMs: 60 * 1000, max: 200,
  message: { error: 'Trop de requêtes.' } });
const authLimiter  = rateLimit({ windowMs: 15 * 60 * 1000, max: 30,
  message: { error: 'Trop de tentatives. Réessayez dans 15 minutes.' } });
const gameLimiter  = rateLimit({ windowMs: 2000, max: 15,
  message: { error: 'Trop de requêtes rapides.' } });
const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60,
  message: { error: 'Trop de requêtes admin.' } });
const inviteLimiter = rateLimit({ windowMs: 60 * 1000, max: 20,
  message: { error: 'Trop d’invitations. Réessayez dans une minute.' } });
app.use(globalLimiter);

function requireSession(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  req.user = { id: req.session.userId };
  next();
}

async function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  const user = await getUserById(req.session.userId);
  if (!user) { req.session.destroy(() => {}); return res.status(401).json({ error: 'Session invalide' }); }
  req.user = user;
  next();
}

async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  // Always re-fetch from DB — never trust cached session data for privilege checks
  const user = await getUserById(req.session.userId);
  if (!user || !user.is_admin) return res.status(403).json({ error: 'Accès refusé' });
  req.user = user;
  next();
}

app.get('/admin', requireAdmin, (_req, res) => {
  res.sendFile(ADMIN_PANEL_FILE);
});

// ── User cache (10s TTL — avoids repeated DB lookups per request) ─────────────
const _uc = new Map();
function _ucGet(id)       { const e = _uc.get(id); return (e && e.exp > Date.now()) ? e.d : null; }
function _ucSet(id, data) { _uc.set(id, { d: data, exp: Date.now() + 60_000 }); }
function _ucDel(id)       { _uc.delete(id); }
const _progressionSchema = { supported: null };

function isMissingColumnError(error) {
  return error && error.code === '42703';
}

function withProgressionDefaults(user) {
  if (!user) return user;
  return {
    daily_streak: 0,
    minigame_pity: 0,
    ...user,
  };
}

// ── DB helpers ────────────────────────────────────────────────────────────────
async function getUserByUsername(username) {
  const richSelect = 'id, username, balance, non_transferable, daily_streak, minigame_pity, password_hash, is_admin';
  const legacySelect = 'id, username, balance, non_transferable, password_hash, is_admin';

  if (_progressionSchema.supported === false) {
    const { data } = await supabase.from('users').select(legacySelect).ilike('username', username).maybeSingle();
    return withProgressionDefaults(data);
  }

  const { data, error } = await supabase.from('users').select(richSelect).ilike('username', username).maybeSingle();
  if (isMissingColumnError(error)) {
    _progressionSchema.supported = false;
    const fallback = await supabase.from('users').select(legacySelect).ilike('username', username).maybeSingle();
    return withProgressionDefaults(fallback.data);
  }
  if (!error) _progressionSchema.supported = true;
  return withProgressionDefaults(data);
}

async function getUserById(id, { fresh = false } = {}) {
  if (!fresh) { const c = _ucGet(id); if (c) return c; }
  const richSelect = 'id, username, balance, non_transferable, last_daily_claim, last_minigame_claim, daily_streak, minigame_pity, is_admin';
  const legacySelect = 'id, username, balance, non_transferable, last_daily_claim, last_minigame_claim, is_admin';

  let data, error;
  if (_progressionSchema.supported === false) {
    ({ data, error } = await supabase.from('users').select(legacySelect).eq('id', id).maybeSingle());
  } else {
    ({ data, error } = await supabase.from('users').select(richSelect).eq('id', id).maybeSingle());
    if (isMissingColumnError(error)) {
      _progressionSchema.supported = false;
      ({ data, error } = await supabase.from('users').select(legacySelect).eq('id', id).maybeSingle());
    } else if (!error) {
      _progressionSchema.supported = true;
    }
  }

  const out = withProgressionDefaults(data);
  if (out) _ucSet(id, out);
  return out;
}

async function createUser(username, passwordHash) {
  const { data, error } = await supabase
    .from('users')
    .insert({ username, password_hash: passwordHash })
    .select().single();
  if (error) throw error;
  return data;
}

async function updateUser(id, patch) {
  const { data } = await supabase
    .from('users').update(patch).eq('id', id)
    .select().single();
  return data;
}

async function getUsersByIds(ids) {
  const uniqueIds = [...new Set((ids || []).filter(Boolean))];
  if (!uniqueIds.length) return [];
  const { data, error } = await supabase
    .from('users')
    .select('id, username, balance')
    .in('id', uniqueIds);
  if (error) throw error;
  return data || [];
}

// Opérations atomiques — évitent la race condition
async function deductBalance(userId, amount, { burnBonus = false } = {}) {
  const { data, error } = await supabase.rpc('deduct_balance', { p_user_id: userId, p_amount: amount, p_burn_bonus: burnBonus });
  if (error) throw { error: 'Solde insuffisant' };
  _ucDel(userId); // invalidate cache — balance changed
  _lbc.exp = 0;
  return data;
}

async function addBalance(userId, amount, { nonTransferable = 0 } = {}) {
  if (amount <= 0) return null;
  const { data, error } = await supabase.rpc('add_balance', {
    p_user_id: userId,
    p_amount: amount,
    p_non_transferable: nonTransferable,
  });
  if (error) throw error;
  _ucDel(userId); // invalidate cache — balance changed
  _lbc.exp = 0;
  return data;
}

// ── Online presence (in-memory heartbeat map) ────────────────────────────────
const _online = new Map(); // userId → timestamp
const ONLINE_TIMEOUT = 60_000; // 60s without heartbeat → offline

app.post('/api/heartbeat', requireSession, (req, res) => {
  _online.set(req.user.id, Date.now());
  res.json({ ok: true });
});

function isOnline(userId) {
  const ts = _online.get(userId);
  return ts && (Date.now() - ts) < ONLINE_TIMEOUT;
}

// ── Live events (SSE) ────────────────────────────────────────────────────────
const _liveClients = new Map(); // userId -> Set<res>

function _trackClient(userId, res) {
  let set = _liveClients.get(userId);
  if (!set) {
    set = new Set();
    _liveClients.set(userId, set);
  }
  set.add(res);
}

function _untrackClient(userId, res) {
  const set = _liveClients.get(userId);
  if (!set) return;
  set.delete(res);
  if (!set.size) _liveClients.delete(userId);
}

function emitToUser(userId, event, payload = {}) {
  const set = _liveClients.get(userId);
  if (!set?.size) return;
  const body = `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const res of set) {
    try { res.write(body); } catch {}
  }
}

function emitToUsers(userIds, event, payload = {}) {
  for (const id of new Set((userIds || []).filter(Boolean))) emitToUser(id, event, payload);
}

app.get('/api/events', requireSession, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  _trackClient(req.user.id, res);
  res.write(`event: ready\ndata: {"ok":true}\n\n`);

  const keepAlive = setInterval(() => {
    try { res.write(': keep-alive\n\n'); } catch {}
  }, 25_000);

  req.on('close', () => {
    clearInterval(keepAlive);
    _untrackClient(req.user.id, res);
  });
});

// ── Player Stats (in-memory, resets on server restart) ──────────────────────
const _stats = new Map(); // userId → { handsPlayed, wins, losses, pushes, blackjacks, busts, biggestWin, biggestBet, totalWagered, totalWon }

function getStats(userId) {
  if (!_stats.has(userId)) {
    _stats.set(userId, {
      handsPlayed: 0, wins: 0, losses: 0, pushes: 0,
      blackjacks: 0, busts: 0, biggestWin: 0, biggestBet: 0,
      totalWagered: 0, totalWon: 0, doubles: 0, splits: 0,
    });
  }
  return _stats.get(userId);
}

function recordGameStats(userId, gs) {
  if (!gs.result) return;
  const st = getStats(userId);
  const totalBet = gs.bets.reduce((a, b) => a + b, 0);
  st.totalWagered += totalBet;
  if (totalBet > st.biggestBet) st.biggestBet = totalBet;

  for (const hr of gs.result.handResults) {
    st.handsPlayed++;
    if (hr.result === 'win') st.wins++;
    else if (hr.result === 'blackjack') { st.wins++; st.blackjacks++; }
    else if (hr.result === 'lose' || hr.result === 'dealer_blackjack') st.losses++;
    else if (hr.result === 'push') st.pushes++;
    if (hr.result === 'bust') st.busts++;
    st.totalWon += hr.win;
    if (hr.win > st.biggestWin) st.biggestWin = hr.win;
  }
}

app.get('/api/user/stats', requireAuth, (req, res) => {
  const st = getStats(req.user.id);
  const winRate = st.handsPlayed > 0 ? ((st.wins / st.handsPlayed) * 100).toFixed(1) : '0.0';
  res.json({ ...st, winRate });
});

// ── Chat (in-memory ring buffer) ─────────────────────────────────────────────
const CHAT_MAX = 80;
const _chatMessages = []; // { id, userId, username, text, ts }
let _chatIdSeq = 0;
const chatLimiter = rateLimit({ windowMs: 10_000, max: 8, keyGenerator: req => req.user?.id || req.ip, standardHeaders: false });

app.get('/api/chat/history', requireAuth, (req, res) => {
  res.json({ messages: _chatMessages.slice(-50) });
});

app.post('/api/chat/send', requireAuth, chatLimiter, (req, res) => {
  const text = (req.body?.text || '').trim().slice(0, 200);
  if (!text) return res.status(400).json({ error: 'Message vide' });

  const msg = {
    id: ++_chatIdSeq,
    userId: req.user.id,
    username: req.user.username,
    text,
    ts: Date.now(),
  };
  _chatMessages.push(msg);
  if (_chatMessages.length > CHAT_MAX) _chatMessages.shift();

  // Broadcast to all connected clients
  for (const [, set] of _liveClients) {
    const body = `event: chat:message\ndata: ${JSON.stringify(msg)}\n\n`;
    for (const r of set) { try { r.write(body); } catch {} }
  }

  res.json({ success: true, message: msg });
});

// ── Game state cache (avoids re-reading 10KB shoe JSON from Supabase each action)
const _gc = new Map();
function _gcGet(uid) { const e = _gc.get(uid); return (e && e.exp > Date.now()) ? e.d : null; }
function _gcSet(uid, d) { _gc.set(uid, { d, exp: Date.now() + 120_000 }); }
function _gcDel(uid) { _gc.delete(uid); }

async function getGame(userId) {
  const cached = _gcGet(userId);
  if (cached) return cached;
  const { data } = await supabase
    .from('active_games').select('game_state')
    .eq('user_id', userId).maybeSingle();
  const gs = data ? data.game_state : null;
  if (gs) _gcSet(userId, gs);
  return gs;
}

async function setGame(userId, gameState) {
  _gcSet(userId, gameState); // update cache immediately — no need to wait for DB
  await supabase.from('active_games').upsert(
    { user_id: userId, game_state: gameState, updated_at: new Date().toISOString() },
    { onConflict: 'user_id' }
  );
}

async function deleteGame(userId) {
  _gcDel(userId);
  await supabase.from('active_games').delete().eq('user_id', userId);
}

// ── Friendships / PvP ────────────────────────────────────────────────────────
const _pgc = new Map();
function _pgcGet(id) { const e = _pgc.get(id); return (e && e.exp > Date.now()) ? e.d : null; }
function _pgcSet(id, d) { _pgc.set(id, { d, exp: Date.now() + 120_000 }); }
function _pgcDel(id) { _pgc.delete(id); }

async function getFriends(userId) {
  const { data, error } = await supabase
    .from('friendships')
    .select('friend_id, created_at')
    .eq('user_id', userId)
    .order('created_at', { ascending: true });
  if (error) throw error;
  const users = await getUsersByIds((data || []).map(row => row.friend_id));
  const usersById = new Map(users.map(user => [user.id, user]));
  return (data || [])
    .map(row => usersById.get(row.friend_id))
    .filter(Boolean)
    .map(user => ({
      id: user.id,
      username: user.username,
      balance: user.balance,
      online: !!isOnline(user.id),
    }))
    .sort((a, b) => a.username.localeCompare(b.username, 'fr', { sensitivity: 'base' }));
}

async function areFriends(userId, friendId) {
  const { data } = await supabase
    .from('friendships')
    .select('friend_id')
    .eq('user_id', userId)
    .eq('friend_id', friendId)
    .maybeSingle();
  return !!data;
}

async function getFriendRequests(userId) {
  const [{ data: incoming, error: incomingError }, { data: outgoing, error: outgoingError }] = await Promise.all([
    supabase
      .from('friend_requests')
      .select('id, from_user_id, to_user_id, status, created_at')
      .eq('to_user_id', userId)
      .eq('status', 'pending')
      .order('created_at', { ascending: false }),
    supabase
      .from('friend_requests')
      .select('id, from_user_id, to_user_id, status, created_at')
      .eq('from_user_id', userId)
      .eq('status', 'pending')
      .order('created_at', { ascending: false }),
  ]);
  if (incomingError) throw incomingError;
  if (outgoingError) throw outgoingError;

  const users = await getUsersByIds([
    ...(incoming || []).map(row => row.from_user_id),
    ...(outgoing || []).map(row => row.to_user_id),
  ]);
  const usersById = new Map(users.map(user => [user.id, user]));
  const mapRequest = (row, otherField) => ({
    id: row.id,
    createdAt: row.created_at,
    userId: row[otherField],
    username: usersById.get(row[otherField])?.username || 'Inconnu',
    online: !!isOnline(row[otherField]),
  });

  return {
    incoming: (incoming || []).map(row => mapRequest(row, 'from_user_id')),
    outgoing: (outgoing || []).map(row => mapRequest(row, 'to_user_id')),
  };
}

async function getPendingFriendRequestBetween(userA, userB) {
  const { data } = await supabase
    .from('friend_requests')
    .select('id, from_user_id, to_user_id, status')
    .eq('status', 'pending')
    .or(`and(from_user_id.eq.${userA},to_user_id.eq.${userB}),and(from_user_id.eq.${userB},to_user_id.eq.${userA})`)
    .maybeSingle();
  return data;
}

const PVP_INVITE_TTL_MS = 60_000;

async function expireStalePvpInvites() {
  const cutoff = new Date(Date.now() - PVP_INVITE_TTL_MS).toISOString();
  const { data: staleInvites, error: selectError } = await supabase
    .from('pvp_invites')
    .select('id, from_user_id, to_user_id')
    .eq('status', 'pending')
    .lt('created_at', cutoff);
  if (selectError) throw selectError;
  if (!staleInvites?.length) return [];

  const inviteIds = staleInvites.map(invite => invite.id);
  const { error: updateError } = await supabase
    .from('pvp_invites')
    .update({ status: 'expired', updated_at: new Date().toISOString() })
    .in('id', inviteIds);
  if (updateError) throw updateError;
  return staleInvites;
}

async function getPendingInvites(userId) {
  const expiredInvites = await expireStalePvpInvites();
  const [{ data: incoming, error: incomingError }, { data: outgoing, error: outgoingError }] = await Promise.all([
    supabase
      .from('pvp_invites')
      .select('id, from_user_id, to_user_id, amount, status, created_at')
      .eq('to_user_id', userId)
      .eq('status', 'pending')
      .order('created_at', { ascending: false }),
    supabase
      .from('pvp_invites')
      .select('id, from_user_id, to_user_id, amount, status, created_at')
      .eq('from_user_id', userId)
      .eq('status', 'pending')
      .order('created_at', { ascending: false }),
  ]);
  if (incomingError) throw incomingError;
  if (outgoingError) throw outgoingError;

  const users = await getUsersByIds([
    ...(incoming || []).map(row => row.from_user_id),
    ...(outgoing || []).map(row => row.to_user_id),
  ]);
  const usersById = new Map(users.map(user => [user.id, user]));
  const mapInvite = (row, otherField) => {
    const other = usersById.get(row[otherField]);
    return {
      id: row.id,
      amount: row.amount,
      createdAt: row.created_at,
      username: other?.username || 'Inconnu',
      userId: row[otherField],
      online: other ? !!isOnline(other.id) : false,
    };
  };

  if (expiredInvites.some(invite => invite.from_user_id === userId || invite.to_user_id === userId)) {
    notifyInvitesUpdated([userId]).catch(() => {});
  }

  return {
    incoming: (incoming || []).map(row => mapInvite(row, 'from_user_id')),
    outgoing: (outgoing || []).map(row => mapInvite(row, 'to_user_id')),
  };
}

async function getPvpGameById(gameId) {
  if (!gameId) return null;
  const cached = _pgcGet(gameId);
  if (cached) return cached;
  const { data, error } = await supabase
    .from('pvp_games')
    .select('id, player_one_id, player_two_id, status, game_state, created_at, updated_at')
    .eq('id', gameId)
    .maybeSingle();
  if (error) throw error;
  if (!data) return null;
  const game = { id: data.id, playerOneId: data.player_one_id, playerTwoId: data.player_two_id, status: data.status, ...data.game_state };
  _pgcSet(game.id, game);
  return game;
}

async function getPvpGameByUser(userId, { includeDismissed = false } = {}) {
  const { data, error } = await supabase
    .from('pvp_games')
    .select('id')
    .or(`player_one_id.eq.${userId},player_two_id.eq.${userId}`)
    .in('status', ['active', 'complete'])
    .order('updated_at', { ascending: false })
    .limit(3);
  if (error) throw error;
  if (!data?.length) return null;
  for (const row of data) {
    const game = await getPvpGameById(row.id);
    if (!game) continue;
    await settlePvpTimeoutIfNeeded(game);
    const dismissedBy = game.dismissedBy || [];
    if (!includeDismissed && game.phase === 'complete' && dismissedBy.includes(userId)) continue;
    return game;
  }
  return null;
}

async function savePvpGame(game) {
  _pgcSet(game.id, game);
  const payload = {
    id: game.id,
    player_one_id: game.playerOneId,
    player_two_id: game.playerTwoId,
    status: game.phase === 'complete' ? 'complete' : 'active',
    game_state: {
      bet: game.bet,
      phase: game.phase,
      players: game.players,
      shoe: game.shoe,
      result: game.result || null,
      dismissedBy: game.dismissedBy || [],
      rematchReady: game.rematchReady || [],
      createdBy: game.createdBy,
      createdAt: game.createdAt,
    },
    updated_at: new Date().toISOString(),
  };

  await supabase
    .from('pvp_games')
    .upsert(payload, { onConflict: 'id' });
}

async function deletePvpGame(gameId) {
  _pgcDel(gameId);
  await supabase.from('pvp_games').delete().eq('id', gameId);
}

function pvpPlayerIndex(game, userId) {
  return game.players.findIndex(player => player.userId === userId);
}

const PVP_IDLE_TIMEOUT_MS = 60_000;

function getPvpLastActionMs(player, game) {
  const raw = player.lastActionAt || game.createdAt || 0;
  const ms = typeof raw === 'number' ? raw : Date.parse(raw);
  return Number.isFinite(ms) ? ms : 0;
}

function resolvePvpTimeout(game) {
  if (!game || game.phase !== 'active') return null;
  const now = Date.now();
  const activePlayers = game.players.filter(player => !player.stood && !isBust(player.hand));
  const timedOut = activePlayers.filter(player => (now - getPvpLastActionMs(player, game)) >= PVP_IDLE_TIMEOUT_MS);
  if (!timedOut.length) return null;

  if (timedOut.length >= 2) {
    return {
      type: 'push',
      reason: 'timeout_both',
      payouts: Object.fromEntries(game.players.map(player => [player.userId, game.bet])),
    };
  }

  const loser = timedOut[0];
  const winner = game.players.find(player => player.userId !== loser.userId);
  if (!winner) return null;
  return {
    type: 'win',
    reason: 'timeout',
    winnerId: winner.userId,
    loserId: loser.userId,
    payouts: { [winner.userId]: game.bet * 2 },
  };
}

function sanitizePvpGame(game, viewerId) {
  if (!game) return null;
  const me = game.players.find(player => player.userId === viewerId);
  const opponent = game.players.find(player => player.userId !== viewerId);
  if (!me || !opponent) return null;
  const opponentInitialHand = Array.isArray(opponent.initialHand) && opponent.initialHand.length
    ? opponent.initialHand
    : opponent.hand.slice(0, 2);
  return {
    id: game.id,
    bet: game.bet,
    phase: game.phase,
    me: {
      id: me.userId,
      username: me.username,
      hand: me.hand,
      total: handValue(me.hand),
      stood: !!me.stood,
      busted: !!isBust(me.hand),
    },
    opponent: {
      id: opponent.userId,
      username: opponent.username,
      previewHand: game.phase === 'complete'
        ? opponent.hand
        : (opponentInitialHand.length ? [opponentInitialHand[0], { hidden: true }] : []),
      initialTotal: handValue(opponentInitialHand),
      total: handValue(opponent.hand),
      stood: !!opponent.stood,
      busted: !!isBust(opponent.hand),
      online: !!isOnline(opponent.userId),
    },
    result: game.result || null,
    rematchReady: game.rematchReady || [],
    opponentDismissed: (game.dismissedBy || []).includes(opponent.userId),
  };
}

async function emitPvpState(game) {
  emitToUsers(
    game.players.map(player => player.userId),
    'pvp:update',
    { gameId: game.id }
  );
}

function resolvePvpGame(game) {
  const [a, b] = game.players;
  const aVal = handValue(a.hand);
  const bVal = handValue(b.hand);
  const aBust = aVal > 21;
  const bBust = bVal > 21;

  let winnerId = null;
  let outcome = 'push';
  if (aBust && bBust) {
    outcome = 'double_bust';
  } else if (aBust && !bBust) {
    winnerId = b.userId;
    outcome = 'opponent_win';
  } else if (!aBust && bBust) {
    winnerId = a.userId;
    outcome = 'opponent_win';
  } else if (aVal === bVal) {
    outcome = 'push';
  } else {
    winnerId = aVal > bVal ? a.userId : b.userId;
    outcome = 'opponent_win';
  }

  const payouts = {};
  if (winnerId) payouts[winnerId] = game.bet * 2;
  else {
    payouts[a.userId] = game.bet;
    payouts[b.userId] = game.bet;
  }

  return {
    winnerId,
    outcome,
    payouts,
    totals: {
      [a.userId]: aVal,
      [b.userId]: bVal,
    },
  };
}

async function settlePvpGame(game) {
  game.phase = 'complete';
  game.result = resolvePvpGame(game);
  game.dismissedBy = [];

  const payouts = Object.entries(game.result.payouts || {});
  for (const [userId, amount] of payouts) await addBalance(userId, amount);
  await savePvpGame(game);
  await emitPvpState(game);
}

async function settleTimedOutPvpGame(game, timeoutResult) {
  game.phase = 'complete';
  game.dismissedBy = [];
  game.result = {
    winnerId: timeoutResult.winnerId || null,
    outcome: timeoutResult.type === 'push' ? 'push' : 'opponent_win',
    reason: timeoutResult.reason,
    payouts: timeoutResult.payouts,
    totals: Object.fromEntries(game.players.map(player => [player.userId, handValue(player.hand)])),
    loserId: timeoutResult.loserId || null,
  };

  for (const [userId, amount] of Object.entries(timeoutResult.payouts || {})) {
    await addBalance(userId, amount);
  }
  await savePvpGame(game);
  await emitPvpState(game);
}

async function settlePvpTimeoutIfNeeded(game) {
  const timeoutResult = resolvePvpTimeout(game);
  if (!timeoutResult) return game;
  await settleTimedOutPvpGame(game, timeoutResult);
  return game;
}

async function ensureUserFreeForPvp(userId) {
  const [singlePlayer, pvp] = await Promise.all([
    getGame(userId),
    getPvpGameByUser(userId, { includeDismissed: true }),
  ]);
  if (singlePlayer && singlePlayer.phase !== 'complete') throw { status: 400, error: 'Terminez votre partie solo avant un 1v1' };
  if (pvp && pvp.phase !== 'complete') throw { status: 400, error: 'Ce joueur est déjà en 1v1' };
}

async function notifyFriendsUpdated(userIds) {
  emitToUsers(userIds, 'friends:update', {});
}

async function notifyInvitesUpdated(userIds) {
  emitToUsers(userIds, 'invites:update', {});
}

async function notifyFriendRequestsUpdated(userIds) {
  emitToUsers(userIds, 'friend_requests:update', {});
}

// ── Card / Deck Utilities ─────────────────────────────────────────────────────
const SUITS = ['♠', '♥', '♦', '♣'];
const RANKS = ['A','2','3','4','5','6','7','8','9','10','J','Q','K'];

function createDeck() {
  const deck = [];
  for (const suit of SUITS)
    for (const rank of RANKS) {
      const fv = parseInt(rank);
      deck.push({ suit, rank, value: isNaN(fv) ? (rank === 'A' ? 11 : 10) : fv });
    }
  return deck;
}

function createShoe(n = 6) {
  let shoe = [];
  for (let i = 0; i < n; i++) shoe = shoe.concat(createDeck());
  for (let i = shoe.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shoe[i], shoe[j]] = [shoe[j], shoe[i]];
  }
  return shoe;
}

function drawCard(shoe) {
  if (shoe.length < 52) { const s = createShoe(); shoe.splice(0, shoe.length, ...s); }
  return shoe.pop();
}

function handValue(hand) {
  let total = 0, aces = 0;
  for (const c of hand) {
    if (!c || c.hidden) continue;
    if (c.rank === 'A') { aces++; total += 11; }
    else total += Math.min(c.value, 10);
  }
  while (total > 21 && aces > 0) { total -= 10; aces--; }
  return total;
}

function isBlackjack(hand) { return hand.length === 2 && handValue(hand) === 21; }
function isBust(hand)      { return handValue(hand) > 21; }

function getNowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function getStartOfServerDaySeconds(date = new Date()) {
  const d = new Date(date);
  d.setHours(0, 0, 0, 0);
  return Math.floor(d.getTime() / 1000);
}

function getNextServerDaySeconds(date = new Date()) {
  const d = new Date(date);
  d.setHours(24, 0, 0, 0);
  return Math.floor(d.getTime() / 1000);
}

function isSameServerDay(tsA, tsB) {
  if (!tsA || !tsB) return false;
  const a = new Date(tsA * 1000);
  const b = new Date(tsB * 1000);
  return (
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
  );
}

function getDailyCooldownSeconds(lastClaim, now = getNowSeconds()) {
  if (!lastClaim || !isSameServerDay(lastClaim, now)) return 0;
  return Math.max(0, getNextServerDaySeconds(new Date(now * 1000)) - now);
}

function getMinigameCooldownSeconds(lastClaim, now = getNowSeconds()) {
  if (!lastClaim) return 0;
  return Math.max(0, (lastClaim + 120) - now);
}

const DAILY_BASE_BONUS = 2000;
const DAILY_STREAK_MILESTONES = [
  { day: 3, bonus: 1000, label: 'Palier Jour 3' },
  { day: 7, bonus: 4000, label: 'Coffre Jour 7' },
  { day: 14, bonus: 8000, label: 'Palier Jour 14' },
  { day: 30, bonus: 20000, label: 'Couronne Jour 30' },
];
const MINIGAME_PITY_CAP = 4;

function getDailyMilestone(streak) {
  return DAILY_STREAK_MILESTONES.find(m => m.day === streak) || null;
}

function getNextDailyMilestone(streak) {
  return DAILY_STREAK_MILESTONES.find(m => m.day > streak) || DAILY_STREAK_MILESTONES[DAILY_STREAK_MILESTONES.length - 1];
}

function getDailyProgress(u) {
  const streak = Math.max(0, u.daily_streak || 0);
  const nextMilestone = getNextDailyMilestone(streak);
  return {
    dailyStreak: streak,
    dailyBaseBonus: DAILY_BASE_BONUS,
    dailyNextMilestoneDay: nextMilestone.day,
    dailyNextMilestoneBonus: nextMilestone.bonus,
  };
}

function getMinigameProgress(u) {
  const pity = Math.max(0, Math.min(MINIGAME_PITY_CAP, u.minigame_pity || 0));
  return {
    minigamePity: pity,
    minigamePityCap: MINIGAME_PITY_CAP,
    minigameGuaranteedReady: pity >= MINIGAME_PITY_CAP,
  };
}

function buildCooldowns(u, now = getNowSeconds()) {
  const dailyCooldown = getDailyCooldownSeconds(u.last_daily_claim, now);
  const minigameCooldown = getMinigameCooldownSeconds(u.last_minigame_claim, now);
  return {
    dailyCooldown,
    minigameCooldown,
    dailyAvailableAt: now + dailyCooldown,
    minigameAvailableAt: now + minigameCooldown,
  };
}

function resolveGame(gs) {
  const dealerVal = handValue(gs.dealerHand);
  const dealerBJ  = isBlackjack(gs.dealerHand);
  let totalWin    = 0;
  const handResults = [];

  for (let i = 0; i < gs.hands.length; i++) {
    const hand     = gs.hands[i];
    const bet      = gs.bets[i];
    const val      = handValue(hand);
    const playerBJ = isBlackjack(hand) && gs.hands.length === 1;

    let result, win = 0;
    if (isBust(hand))                     { result = 'bust'; }
    else if (playerBJ && dealerBJ)        { result = 'push';             win = bet; }
    else if (playerBJ)                    { result = 'blackjack';        win = bet + Math.floor(bet * 1.5); }
    else if (dealerBJ)                    { result = 'dealer_blackjack'; }
    else if (isBust(gs.dealerHand) || val > dealerVal) { result = 'win'; win = bet * 2; }
    else if (val === dealerVal)           { result = 'push';             win = bet; }
    else                                  { result = 'lose'; }

    totalWin += win;
    handResults.push({ result, win, value: val, bet });
  }
  return { handResults, totalWin, dealerValue: dealerVal };
}

function sanitize(gs) {
  const { shoe, ...state } = gs;
  const out = { ...state, shoeRemaining: shoe ? shoe.length : 0 };
  if (state.phase === 'player_turn') out.dealerHand = [state.dealerHand[0], { hidden: true }];
  return out;
}

// ── Auth Routes ───────────────────────────────────────────────────────────────
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { username, password } = req.body ?? {};
  if (!username || !password)
    return res.status(400).json({ error: "Nom d'utilisateur et mot de passe requis" });
  if (username.length < 3 || username.length > 20)
    return res.status(400).json({ error: "Nom d'utilisateur : 3–20 caractères" });
  if (!/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: "Nom d'utilisateur : lettres, chiffres et _ uniquement" });
  if (containsBannedWord(username))
    return res.status(400).json({ error: "Ce nom d'utilisateur n'est pas autorisé" });
  if (password.length < 6)
    return res.status(400).json({ error: 'Mot de passe : 6 caractères minimum' });

  if (await getUserByUsername(username))
    return res.status(409).json({ error: "Ce nom d'utilisateur est déjà pris" });

  try {
    const hash = await bcrypt.hash(password, 12);
    const user = await createUser(username, hash);
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Erreur serveur' });
      req.session.userId = user.id;
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ error: 'Erreur serveur' });
        res.json({ success: true, user: { id: user.id, username: user.username, balance: user.balance, nonTransferable: user.non_transferable || 0 } });
      });
    });
  } catch(e) {
    console.error(e); res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { username, password } = req.body ?? {};
  if (!username || !password) return res.status(400).json({ error: 'Champs requis' });

  const user = await getUserByUsername(username);
  if (!user || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).json({ error: 'Identifiants incorrects' });

  // Regenerate session ID after auth to prevent session fixation
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Erreur serveur' });
    req.session.userId = user.id;
    req.session.save((saveErr) => {
      if (saveErr) return res.status(500).json({ error: 'Erreur serveur' });
      res.json({ success: true, user: { id: user.id, username: user.username, balance: user.balance, nonTransferable: user.non_transferable || 0 } });
    });
  });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// ── User Routes ───────────────────────────────────────────────────────────────
function respondMe(req, res) {
  const u   = req.user;
  const now = getNowSeconds();
  const cooldowns = buildCooldowns(u, now);
  res.json({
    serverNow: now,
    user: {
      id: u.id, username: u.username, balance: u.balance,
      nonTransferable: u.non_transferable || 0,
      ...getDailyProgress(u),
      ...getMinigameProgress(u),
      ...cooldowns,
    }
  });
}
app.get('/api/auth/me',  requireAuth, respondMe);
app.get('/api/user/me',  requireAuth, respondMe);

app.post('/api/user/change-username', requireAuth, async (req, res) => {
  const newName = (req.body?.username || '').trim();
  if (!newName) return res.status(400).json({ error: "Nom d'utilisateur requis" });
  if (newName.length < 3 || newName.length > 20)
    return res.status(400).json({ error: "Nom d'utilisateur : 3–20 caractères" });
  if (!/^[a-zA-Z0-9_]+$/.test(newName))
    return res.status(400).json({ error: "Lettres, chiffres et _ uniquement" });
  if (containsBannedWord(newName))
    return res.status(400).json({ error: "Ce nom d'utilisateur n'est pas autorisé" });
  if (newName.toLowerCase() === req.user.username.toLowerCase())
    return res.status(400).json({ error: "C'est déjà votre pseudo" });

  const existing = await getUserByUsername(newName);
  if (existing) return res.status(409).json({ error: "Ce nom d'utilisateur est déjà pris" });

  const { error } = await supabase.from('users').update({ username: newName }).eq('id', req.user.id);
  if (error) return res.status(500).json({ error: 'Erreur serveur' });

  _ucDel(req.user.id);
  _lbc.exp = 0;
  console.log(`[USER] ${req.user.username} → renamed to ${newName}`);
  res.json({ success: true, username: newName });
});

app.post('/api/user/daily-bonus', requireAuth, async (req, res) => {
  const now = getNowSeconds();
  const user = await getUserById(req.user.id, { fresh: true });
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const startOfToday = getStartOfServerDaySeconds(new Date(now * 1000));
  const compatibilityMode = _progressionSchema.supported === false;

  if (compatibilityMode) {
    const { data, error } = await supabase.from('users')
      .update({ last_daily_claim: now })
      .eq('id', req.user.id)
      .or(`last_daily_claim.is.null,last_daily_claim.lt.${startOfToday}`)
      .select('last_daily_claim').maybeSingle();

    if (!data || error) {
      const cooldown = getDailyCooldownSeconds(user.last_daily_claim, now);
      return res.status(429).json({
        error: 'Bonus déjà réclamé aujourd’hui',
        serverNow: now,
        cooldown,
        availableAt: now + cooldown,
        ...getDailyProgress(user),
      });
    }

    const newBal = await addBalance(req.user.id, DAILY_BASE_BONUS, { nonTransferable: DAILY_BASE_BONUS });
    const cooldown = getDailyCooldownSeconds(now, now);
    _ucDel(req.user.id);
    return res.json({
      success: true,
      bonus: DAILY_BASE_BONUS,
      baseBonus: DAILY_BASE_BONUS,
      streak: 0,
      milestoneBonus: 0,
      milestoneLabel: '',
      balance: newBal,
      serverNow: now,
      cooldown,
      availableAt: now + cooldown,
      ...getDailyProgress(user),
      compatibilityMode: true,
    });
  }

  const startOfYesterday = startOfToday - 86400;

  const previousClaim = user.last_daily_claim || 0;
  let nextStreak = 1;
  if (previousClaim >= startOfYesterday && previousClaim < startOfToday) {
    nextStreak = Math.max(1, (user.daily_streak || 0) + 1);
  } else if (previousClaim >= startOfToday) {
    nextStreak = Math.max(1, user.daily_streak || 1);
  }

  // Atomic: update only succeeds if the last claim is before today's server date.
  const { data } = await supabase.from('users')
    .update({ last_daily_claim: now, daily_streak: nextStreak })
    .eq('id', req.user.id)
    .or(`last_daily_claim.is.null,last_daily_claim.lt.${startOfToday}`)
    .select('last_daily_claim,daily_streak').maybeSingle();

  if (!data) {
    const cooldown = getDailyCooldownSeconds(user.last_daily_claim, now);
    return res.status(429).json({
      error: 'Bonus déjà réclamé aujourd’hui',
      serverNow: now,
      cooldown,
      availableAt: now + cooldown,
      ...getDailyProgress(user),
    });
  }
  const milestone = getDailyMilestone(nextStreak);
  const milestoneBonus = milestone ? milestone.bonus : 0;
  const totalBonus = DAILY_BASE_BONUS + milestoneBonus;
  const newBal = await addBalance(req.user.id, totalBonus, { nonTransferable: totalBonus });
  const cooldown = getDailyCooldownSeconds(now, now);
  const updatedUser = { ...user, last_daily_claim: now, daily_streak: nextStreak };
  _ucDel(req.user.id);
  res.json({
    success: true,
    bonus: totalBonus,
    baseBonus: DAILY_BASE_BONUS,
    streak: nextStreak,
    milestoneBonus,
    milestoneLabel: milestone ? milestone.label : '',
    balance: newBal,
    serverNow: now,
    cooldown,
    availableAt: now + cooldown,
    ...getDailyProgress(updatedUser),
  });
});

app.post('/api/user/minigame', requireAuth, async (req, res) => {
  const now = getNowSeconds();
  const user = await getUserById(req.user.id, { fresh: true });
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const compatibilityMode = _progressionSchema.supported === false;
  // Atomic: update only succeeds if cooldown has passed — prevents double-claim race condition
  const { data } = await supabase.from('users')
    .update({ last_minigame_claim: now })
    .eq('id', req.user.id)
    .lt('last_minigame_claim', now - 120)
    .select('last_minigame_claim').maybeSingle();

  if (!data) {
    const cooldown = getMinigameCooldownSeconds(user.last_minigame_claim, now);
    return res.status(429).json({
      error: 'Spatule en recharge',
      serverNow: now,
      cooldown,
      availableAt: now + cooldown,
      ...getMinigameProgress(user),
    });
  }

  if (compatibilityMode) {
    const SMALL_R = [30, 40, 50, 60, 70, 80];
    const MED_R   = [200, 300, 500, 1000];
    const JACK_R  = [2000, 5000];
    const roll = Math.random();
    let reward;
    if      (roll < 0.70) reward = SMALL_R[Math.floor(Math.random() * SMALL_R.length)];
    else if (roll < 0.95) reward = MED_R[Math.floor(Math.random() * MED_R.length)];
    else                  reward = JACK_R[Math.floor(Math.random() * JACK_R.length)];

    const newBal = await addBalance(req.user.id, reward, { nonTransferable: reward });
    const cooldown = getMinigameCooldownSeconds(now, now);
    _ucDel(req.user.id);
    return res.json({
      success: true,
      reward,
      rarity: reward >= 1000 ? 'jackpot' : reward >= 101 ? 'medium' : 'small',
      pityBefore: 0,
      pityAfter: 0,
      guaranteed: false,
      balance: newBal,
      serverNow: now,
      cooldown,
      availableAt: now + cooldown,
      ...getMinigameProgress(user),
      compatibilityMode: true,
    });
  }

  const pityBefore = Math.max(0, Math.min(MINIGAME_PITY_CAP, user.minigame_pity || 0));
  const guaranteed = pityBefore >= MINIGAME_PITY_CAP;
  const roll = Math.random();
  let reward;
  let rarity = 'small';
  const SMALL_REWARDS   = [30, 40, 50, 60, 70, 80];
  const MEDIUM_REWARDS  = [200, 300, 500, 1000];
  const JACKPOT_REWARDS = [2000, 5000];
  if (guaranteed || roll >= 0.95) {
    reward = JACKPOT_REWARDS[Math.floor(Math.random() * JACKPOT_REWARDS.length)];
    rarity = 'jackpot';
  } else if (roll >= 0.70) {
    reward = MEDIUM_REWARDS[Math.floor(Math.random() * MEDIUM_REWARDS.length)];
    rarity = 'medium';
  } else {
    reward = SMALL_REWARDS[Math.floor(Math.random() * SMALL_REWARDS.length)];
  }

  const nextPity = rarity === 'jackpot' ? 0 : Math.min(MINIGAME_PITY_CAP, pityBefore + 1);
  await supabase
    .from('users')
    .update({ minigame_pity: nextPity })
    .eq('id', req.user.id);

  const newBal = await addBalance(req.user.id, reward, { nonTransferable: reward });
  const cooldown = getMinigameCooldownSeconds(now, now);
  const updatedUser = { ...user, last_minigame_claim: now, minigame_pity: nextPity };
  _ucDel(req.user.id);
  res.json({
    success: true,
    reward,
    rarity,
    pityBefore,
    pityAfter: nextPity,
    guaranteed,
    balance: newBal,
    serverNow: now,
    cooldown,
    availableAt: now + cooldown,
    ...getMinigameProgress(updatedUser),
  });
});

// ── Leaderboard ───────────────────────────────────────────────────────────────
const _lbc = { data: null, exp: 0 };
async function getLeaderboardData() {
  const now = Date.now();
  if (_lbc.data && _lbc.exp > now) return _lbc.data;

  const pageSize = 1000;
  let from = 0;
  let sorted = [];

  while (true) {
    const { data, error } = await supabase
      .from('users')
      .select('id, username, balance')
      .eq('is_admin', false)
      .order('balance', { ascending: false })
      .range(from, from + pageSize - 1);

    if (error) throw error;
    if (!data || data.length === 0) break;

    sorted = sorted.concat(data);
    if (data.length < pageSize) break;
    from += pageSize;
  }

  _lbc.data = sorted;
  _lbc.exp = now + 10_000;
  return _lbc.data;
}

app.get('/api/leaderboard', requireSession, async (req, res) => {
  const sorted = await getLeaderboardData();
  const wantsFull = req.query.full === '1';
  if (!sorted.length) return res.json({ top10: [], me: null });

  if (wantsFull) {
    const players = sorted.map((u, i) => ({
      rank: i + 1, username: u.username, balance: u.balance, isMe: u.id === req.user.id, online: isOnline(u.id),
    }));
    return res.json({ players });
  }

  const top10 = sorted.slice(0, 10).map((u, i) => ({
    rank: i + 1, username: u.username, balance: u.balance, isMe: u.id === req.user.id, online: isOnline(u.id),
  }));
  const myRank = sorted.findIndex(u => u.id === req.user.id) + 1;
  const meUser = myRank > 0 ? sorted[myRank - 1] : null;
  const me = myRank > 0 && myRank > 10
    ? { rank: myRank, username: meUser.username, balance: meUser.balance, isMe: true, online: isOnline(req.user.id) }
    : null;

  res.json({ top10, me });
});

// ── User Search (for gift autocomplete) ──────────────────────────────────────
app.get('/api/user/search', requireAuth, async (req, res) => {
  const q = (req.query.q || '').trim().toLowerCase();
  if (!q || q.length < 1) return res.json({ users: [] });

  const { data } = await supabase
    .from('users')
    .select('username')
    .ilike('username', `${q}%`)
    .neq('id', req.user.id)
    .limit(6);

  res.json({ users: (data || []).map(u => u.username) });
});

// ── Friends ──────────────────────────────────────────────────────────────────
app.get('/api/friends', requireAuth, async (req, res) => {
  const friends = await getFriends(req.user.id);
  res.json({ friends });
});

app.get('/api/friends/requests', requireAuth, async (req, res) => {
  const requests = await getFriendRequests(req.user.id);
  res.json(requests);
});

app.post('/api/friends/request', requireAuth, async (req, res) => {
  const username = String(req.body?.username || '').trim();
  if (!username) return res.status(400).json({ error: 'Pseudo requis' });

  const friend = await getUserByUsername(username);
  if (!friend || friend.is_admin) return res.status(404).json({ error: 'Joueur introuvable' });
  if (friend.id === req.user.id) return res.status(400).json({ error: 'Vous ne pouvez pas vous ajouter' });
  if (await areFriends(req.user.id, friend.id)) return res.status(409).json({ error: 'Déjà dans vos amis' });
  const existingRequest = await getPendingFriendRequestBetween(req.user.id, friend.id);
  if (existingRequest) return res.status(409).json({ error: 'Une demande est déjà en attente' });

  const { error } = await supabase.from('friend_requests').insert({
    from_user_id: req.user.id,
    to_user_id: friend.id,
    status: 'pending',
  });
  if (error) return res.status(500).json({ error: 'Erreur serveur' });

  await notifyFriendRequestsUpdated([req.user.id, friend.id]);
  res.json({ success: true });
});

app.post('/api/friends/requests/:id/accept', requireAuth, async (req, res) => {
  const requestId = req.params.id;
  const { data: request } = await supabase
    .from('friend_requests')
    .select('id, from_user_id, to_user_id, status')
    .eq('id', requestId)
    .eq('to_user_id', req.user.id)
    .maybeSingle();
  if (!request || request.status !== 'pending') return res.status(404).json({ error: 'Demande introuvable' });
  if (await areFriends(request.from_user_id, request.to_user_id)) {
    await supabase.from('friend_requests').update({ status: 'accepted', updated_at: new Date().toISOString() }).eq('id', requestId);
    await notifyFriendRequestsUpdated([request.from_user_id, request.to_user_id]);
    return res.json({ success: true });
  }

  const rows = [
    { user_id: request.from_user_id, friend_id: request.to_user_id },
    { user_id: request.to_user_id, friend_id: request.from_user_id },
  ];
  const { error } = await supabase.from('friendships').insert(rows);
  if (error) return res.status(500).json({ error: 'Erreur serveur' });

  await supabase.from('friend_requests').update({ status: 'accepted', updated_at: new Date().toISOString() }).eq('id', requestId);
  await notifyFriendRequestsUpdated([request.from_user_id, request.to_user_id]);
  await notifyFriendsUpdated([request.from_user_id, request.to_user_id]);
  res.json({ success: true });
});

app.post('/api/friends/requests/:id/decline', requireAuth, async (req, res) => {
  const requestId = req.params.id;
  const { data: request } = await supabase
    .from('friend_requests')
    .select('id, from_user_id, to_user_id, status')
    .eq('id', requestId)
    .eq('to_user_id', req.user.id)
    .maybeSingle();
  if (!request || request.status !== 'pending') return res.status(404).json({ error: 'Demande introuvable' });

  await supabase.from('friend_requests').update({ status: 'declined', updated_at: new Date().toISOString() }).eq('id', requestId);
  await notifyFriendRequestsUpdated([request.from_user_id, request.to_user_id]);
  res.json({ success: true });
});

app.post('/api/friends/requests/:id/cancel', requireAuth, async (req, res) => {
  const requestId = req.params.id;
  const { data: request } = await supabase
    .from('friend_requests')
    .select('id, from_user_id, to_user_id, status')
    .eq('id', requestId)
    .eq('from_user_id', req.user.id)
    .maybeSingle();
  if (!request || request.status !== 'pending') return res.status(404).json({ error: 'Demande introuvable' });

  await supabase.from('friend_requests').update({ status: 'cancelled', updated_at: new Date().toISOString() }).eq('id', requestId);
  await notifyFriendRequestsUpdated([request.from_user_id, request.to_user_id]);
  res.json({ success: true });
});

app.delete('/api/friends/:username', requireAuth, async (req, res) => {
  const username = decodeURIComponent(req.params.username || '').trim();
  if (!username) return res.status(400).json({ error: 'Pseudo requis' });

  const friend = await getUserByUsername(username);
  if (!friend) return res.status(404).json({ error: 'Joueur introuvable' });

  await Promise.all([
    supabase.from('friendships').delete().eq('user_id', req.user.id).eq('friend_id', friend.id),
    supabase.from('friendships').delete().eq('user_id', friend.id).eq('friend_id', req.user.id),
  ]);

  await notifyFriendsUpdated([req.user.id, friend.id]);
  res.json({ success: true });
});

// ── Transfer / Gift ──────────────────────────────────────────────────────────
const transferLimiter = rateLimit({ windowMs: 60 * 1000, max: 10,
  message: { error: 'Trop de transferts. Réessayez dans une minute.' } });

app.post('/api/user/transfer', requireAuth, transferLimiter, async (req, res) => {
  const { to, amount } = req.body || {};
  const amt = parseInt(amount);

  if (!to || typeof to !== 'string' || to.trim().length === 0)
    return res.status(400).json({ error: 'Pseudo du destinataire requis' });
  if (isNaN(amt) || amt < 1)
    return res.status(400).json({ error: 'Montant minimum : 1 🥞' });
  if (amt > 999999999)
    return res.status(400).json({ error: 'Montant maximum : 999 999 999 🥞' });

  const sender = req.user;
  if (to.trim().toLowerCase() === sender.username.toLowerCase())
    return res.status(400).json({ error: 'Vous ne pouvez pas vous envoyer des crêpes' });

  const recipient = await getUserByUsername(to.trim());
  if (!recipient)
    return res.status(404).json({ error: 'Joueur introuvable' });

  const transferable = Math.max(0, sender.balance - (sender.non_transferable || 0));
  if (amt > transferable)
    return res.status(400).json({ error: transferable === 0
      ? 'Vous ne pouvez pas transférer vos bonus non transférables'
      : `Montant transférable : ${transferable.toLocaleString('fr-FR')} 🥞 (les bonus non transférables sont exclus)` });

  try {
    const newBal = await deductBalance(sender.id, amt);
    await addBalance(recipient.id, amt);
    // Log the gift
    await supabase.from('gift_log').insert({ from_user_id: sender.id, to_user_id: recipient.id, amount: amt });
    _lbc.exp = 0; // invalidate leaderboard cache
    // Notify recipient in real time
    emitToUser(recipient.id, 'gift:received', { from: sender.username, amount: amt });
    res.json({ success: true, balance: newBal });
  } catch(e) {
    res.status(400).json({ error: e.error || 'Erreur lors du transfert' });
  }
});

// ── Gifts received ───────────────────────────────────────────────────────────
app.get('/api/user/gifts-received', requireAuth, async (req, res) => {
  try {
    const { data } = await supabase
      .from('gift_log')
      .select('amount, created_at, from_user_id')
      .eq('to_user_id', req.user.id)
      .order('created_at', { ascending: false })
      .limit(10);
    if (!data || data.length === 0) return res.json([]);
    // Resolve sender usernames
    const ids = [...new Set(data.map(g => g.from_user_id))];
    const { data: users } = await supabase.from('users').select('id, username').in('id', ids);
    const nameMap = {};
    (users || []).forEach(u => nameMap[u.id] = u.username);
    res.json(data.map(g => ({ from: nameMap[g.from_user_id] || '???', amount: g.amount, at: g.created_at })));
  } catch(e) {
    res.json([]);
  }
});

// ── PvP / Friends 1v1 ────────────────────────────────────────────────────────
app.get('/api/pvp/invites', requireAuth, async (req, res) => {
  const invites = await getPendingInvites(req.user.id);
  res.json(invites);
});

app.post('/api/pvp/invite', requireAuth, inviteLimiter, async (req, res) => {
  await expireStalePvpInvites();
  const username = String(req.body?.to || '').trim();
  const amount = parseInt(req.body?.amount);
  if (!username) return res.status(400).json({ error: 'Ami requis' });
  if (isNaN(amount) || amount < 10 || amount > 999999999) {
    return res.status(400).json({ error: 'Mise 1v1 invalide (10 à 999 999 999 🥞)' });
  }
  if (req.user.balance < amount) {
    return res.status(400).json({ error: 'Solde insuffisant pour cette invitation' });
  }

  const target = await getUserByUsername(username);
  if (!target || target.is_admin) return res.status(404).json({ error: 'Joueur introuvable' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'Impossible de vous défier vous-même' });
  if (!(await areFriends(req.user.id, target.id))) {
    return res.status(403).json({ error: 'Vous pouvez inviter vos amis uniquement' });
  }

  try {
    await Promise.all([ensureUserFreeForPvp(req.user.id), ensureUserFreeForPvp(target.id)]);
  } catch (e) {
    return res.status(e.status || 400).json({ error: e.error || '1v1 indisponible' });
  }

  const { data: existing } = await supabase
    .from('pvp_invites')
    .select('id')
    .eq('status', 'pending')
    .or(`and(from_user_id.eq.${req.user.id},to_user_id.eq.${target.id}),and(from_user_id.eq.${target.id},to_user_id.eq.${req.user.id})`);
  if (existing?.length) return res.status(409).json({ error: 'Une invitation est déjà en attente avec cet ami' });

  const { error } = await supabase.from('pvp_invites').insert({
    from_user_id: req.user.id,
    to_user_id: target.id,
    amount,
    status: 'pending',
  });
  if (error) return res.status(500).json({ error: 'Erreur serveur' });

  await notifyInvitesUpdated([req.user.id, target.id]);
  res.json({ success: true });
});

app.post('/api/pvp/invites/:id/cancel', requireAuth, async (req, res) => {
  await expireStalePvpInvites();
  const inviteId = req.params.id;
  const { data: invite } = await supabase
    .from('pvp_invites')
    .select('id, from_user_id, to_user_id, status')
    .eq('id', inviteId)
    .eq('from_user_id', req.user.id)
    .maybeSingle();
  if (!invite || invite.status !== 'pending') return res.status(404).json({ error: 'Invitation introuvable' });

  await supabase.from('pvp_invites').update({ status: 'cancelled', updated_at: new Date().toISOString() }).eq('id', inviteId);
  await notifyInvitesUpdated([invite.from_user_id, invite.to_user_id]);
  res.json({ success: true });
});

app.post('/api/pvp/invites/:id/decline', requireAuth, async (req, res) => {
  await expireStalePvpInvites();
  const inviteId = req.params.id;
  const { data: invite } = await supabase
    .from('pvp_invites')
    .select('id, from_user_id, to_user_id, status')
    .eq('id', inviteId)
    .eq('to_user_id', req.user.id)
    .maybeSingle();
  if (!invite || invite.status !== 'pending') return res.status(404).json({ error: 'Invitation introuvable' });

  await supabase.from('pvp_invites').update({ status: 'declined', updated_at: new Date().toISOString() }).eq('id', inviteId);
  await notifyInvitesUpdated([invite.from_user_id, invite.to_user_id]);
  res.json({ success: true });
});

app.post('/api/pvp/invites/:id/accept', requireAuth, inviteLimiter, async (req, res) => {
  await expireStalePvpInvites();
  const inviteId = req.params.id;
  const { data: invite } = await supabase
    .from('pvp_invites')
    .select('id, from_user_id, to_user_id, amount, status')
    .eq('id', inviteId)
    .eq('to_user_id', req.user.id)
    .maybeSingle();
  if (!invite || invite.status !== 'pending') return res.status(404).json({ error: 'Invitation introuvable' });

  const challenger = await getUserById(invite.from_user_id, { fresh: true });
  const opponent = await getUserById(invite.to_user_id, { fresh: true });
  if (!challenger || !opponent) return res.status(404).json({ error: 'Joueur introuvable' });
  if (!(await areFriends(challenger.id, opponent.id))) return res.status(403).json({ error: 'Cette invitation n’est plus valide' });

  try {
    await Promise.all([ensureUserFreeForPvp(challenger.id), ensureUserFreeForPvp(opponent.id)]);
  } catch (e) {
    return res.status(e.status || 400).json({ error: e.error || '1v1 indisponible' });
  }

  try {
    await deductBalance(challenger.id, invite.amount, { burnBonus: true });
  } catch {
    return res.status(400).json({ error: `${challenger.username} n’a plus assez de crêpes` });
  }

  try {
    await deductBalance(opponent.id, invite.amount, { burnBonus: true });
  } catch {
    await addBalance(challenger.id, invite.amount);
    return res.status(400).json({ error: 'Solde insuffisant pour accepter ce 1v1' });
  }

  const shoe = createShoe();
  const game = {
    id: crypto.randomUUID(),
    playerOneId: challenger.id,
    playerTwoId: opponent.id,
    createdBy: challenger.id,
    createdAt: new Date().toISOString(),
    bet: invite.amount,
    phase: 'active',
    dismissedBy: [],
    players: [
      { userId: challenger.id, username: challenger.username, hand: [drawCard(shoe), drawCard(shoe)], initialHand: [], stood: false },
      { userId: opponent.id, username: opponent.username, hand: [drawCard(shoe), drawCard(shoe)], initialHand: [], stood: false },
    ],
    shoe,
    result: null,
  };

  game.players.forEach(player => {
    player.initialHand = player.hand.slice(0, 2);
    player.lastActionAt = Date.now();
  });

  for (const player of game.players) {
    if (handValue(player.hand) === 21) player.stood = true;
  }

  await savePvpGame(game);
  await supabase
    .from('pvp_invites')
    .update({ status: 'accepted', game_id: game.id, updated_at: new Date().toISOString() })
    .eq('id', inviteId);
  await supabase
    .from('pvp_invites')
    .update({ status: 'superseded', updated_at: new Date().toISOString() })
    .neq('id', inviteId)
    .eq('status', 'pending')
    .or(`from_user_id.eq.${challenger.id},to_user_id.eq.${challenger.id},from_user_id.eq.${opponent.id},to_user_id.eq.${opponent.id}`);

  if (game.players.every(player => player.stood || isBust(player.hand))) {
    await settlePvpGame(game);
  } else {
    await emitPvpState(game);
  }
  await notifyInvitesUpdated([challenger.id, opponent.id]);
  res.json({ success: true, game: sanitizePvpGame(game, req.user.id) });
});

app.get('/api/pvp/game/state', requireAuth, async (req, res) => {
  const game = await getPvpGameByUser(req.user.id);
  if (!game) return res.json({ game: null });
  const user = await getUserById(req.user.id, { fresh: true });
  res.json({ game: sanitizePvpGame(game, req.user.id), balance: user.balance });
});

app.post('/api/pvp/game/hit', requireAuth, gameLimiter, async (req, res) => {
  const game = await getPvpGameByUser(req.user.id);
  const user = await getUserById(req.user.id, { fresh: true });
  if (!game) return res.json({ success: false, game: null, balance: user.balance, error: 'Aucun 1v1 en cours' });
  if (game.phase !== 'active') {
    return res.json({ success: false, game: sanitizePvpGame(game, req.user.id), balance: user.balance, error: 'Le 1v1 est terminé' });
  }

  const idx = pvpPlayerIndex(game, req.user.id);
  if (idx < 0) return res.status(403).json({ error: 'Accès refusé' });
  const player = game.players[idx];
  if (player.stood || isBust(player.hand)) {
    return res.json({ success: false, game: sanitizePvpGame(game, req.user.id), balance: user.balance, error: 'Action impossible' });
  }

  player.hand.push(drawCard(game.shoe));
  player.lastActionAt = Date.now();
  if (handValue(player.hand) >= 21) player.stood = true;

  if (game.players.every(p => p.stood || isBust(p.hand))) await settlePvpGame(game);
  else {
    await savePvpGame(game);
    await emitPvpState(game);
  }

  const freshUser = await getUserById(req.user.id, { fresh: true });
  res.json({ success: true, game: sanitizePvpGame(game, req.user.id), balance: freshUser.balance });
});

app.post('/api/pvp/game/stand', requireAuth, gameLimiter, async (req, res) => {
  const game = await getPvpGameByUser(req.user.id);
  const user = await getUserById(req.user.id, { fresh: true });
  if (!game) return res.json({ success: false, game: null, balance: user.balance, error: 'Aucun 1v1 en cours' });
  if (game.phase !== 'active') {
    return res.json({ success: false, game: sanitizePvpGame(game, req.user.id), balance: user.balance, error: 'Le 1v1 est terminé' });
  }

  const idx = pvpPlayerIndex(game, req.user.id);
  if (idx < 0) return res.status(403).json({ error: 'Accès refusé' });
  if (game.players[idx].stood || isBust(game.players[idx].hand)) {
    return res.json({ success: false, game: sanitizePvpGame(game, req.user.id), balance: user.balance, error: 'Action impossible' });
  }
  game.players[idx].stood = true;
  game.players[idx].lastActionAt = Date.now();

  if (game.players.every(player => player.stood || isBust(player.hand))) await settlePvpGame(game);
  else {
    await savePvpGame(game);
    await emitPvpState(game);
  }

  const freshUser = await getUserById(req.user.id, { fresh: true });
  res.json({ success: true, game: sanitizePvpGame(game, req.user.id), balance: freshUser.balance });
});

app.post('/api/pvp/game/dismiss', requireAuth, async (req, res) => {
  const game = await getPvpGameByUser(req.user.id, { includeDismissed: true });
  if (!game || game.phase !== 'complete') return res.json({ success: true });

  const dismissedBy = new Set(game.dismissedBy || []);
  dismissedBy.add(req.user.id);
  game.dismissedBy = [...dismissedBy];

  if (game.dismissedBy.includes(game.playerOneId) && game.dismissedBy.includes(game.playerTwoId)) {
    await deletePvpGame(game.id);
  } else {
    await savePvpGame(game);
  }

  await emitToUsers([game.playerOneId, game.playerTwoId], 'pvp:update', { gameId: game.id });
  res.json({ success: true });
});

const _rematchLocks = new Set();
app.post('/api/pvp/game/rematch', requireAuth, inviteLimiter, async (req, res) => {
  const game = await getPvpGameByUser(req.user.id, { includeDismissed: true });
  if (!game || game.phase !== 'complete') return res.status(400).json({ error: 'Aucune partie terminée' });
  if (_rematchLocks.has(game.id)) return res.status(409).json({ error: 'Revanche en cours de création' });

  const dismissedBy = game.dismissedBy || [];
  if (dismissedBy.length > 0) return res.status(400).json({ error: 'L\'adversaire a quitté la partie' });

  const rematchReady = new Set(game.rematchReady || []);
  rematchReady.add(req.user.id);
  game.rematchReady = [...rematchReady];

  const bothReady = game.rematchReady.includes(game.playerOneId) && game.rematchReady.includes(game.playerTwoId);

  if (!bothReady) {
    await savePvpGame(game);
    await emitToUsers([game.playerOneId, game.playerTwoId], 'pvp:update', { gameId: game.id });
    return res.json({ success: true, waiting: true });
  }

  // Both ready — lock and start a new game with the same bet
  _rematchLocks.add(game.id);
  try {
    const p1 = await getUserById(game.playerOneId, { fresh: true });
    const p2 = await getUserById(game.playerTwoId, { fresh: true });
    if (!p1 || !p2) return res.status(404).json({ error: 'Joueur introuvable' });
    if (!(await areFriends(p1.id, p2.id))) return res.status(403).json({ error: 'Vous devez être amis pour rejouer' });

    const bet = game.bet;
    try { await deductBalance(p1.id, bet, { burnBonus: true }); } catch {
      return res.status(400).json({ error: `${p1.username} n'a plus assez de crêpes` });
    }
    try { await deductBalance(p2.id, bet, { burnBonus: true }); } catch {
      await addBalance(p1.id, bet);
      return res.status(400).json({ error: `${p2.username} n'a plus assez de crêpes` });
    }

    // Clean up old game
    await deletePvpGame(game.id);

    const shoe = createShoe();
    const newGame = {
      id: crypto.randomUUID(),
      playerOneId: p1.id,
      playerTwoId: p2.id,
      createdBy: req.user.id,
      createdAt: new Date().toISOString(),
      bet,
      phase: 'active',
      dismissedBy: [],
      rematchReady: [],
      players: [
        { userId: p1.id, username: p1.username, hand: [drawCard(shoe), drawCard(shoe)], initialHand: [], stood: false },
        { userId: p2.id, username: p2.username, hand: [drawCard(shoe), drawCard(shoe)], initialHand: [], stood: false },
      ],
      shoe,
      result: null,
    };

    newGame.players.forEach(player => {
      player.initialHand = player.hand.slice(0, 2);
      player.lastActionAt = Date.now();
    });

    for (const player of newGame.players) {
      if (handValue(player.hand) === 21) player.stood = true;
    }

    await savePvpGame(newGame);

    if (newGame.players.every(player => player.stood || isBust(player.hand))) {
      await settlePvpGame(newGame);
    } else {
      await emitPvpState(newGame);
    }

    const freshUser = await getUserById(req.user.id, { fresh: true });
    res.json({ success: true, waiting: false, game: sanitizePvpGame(newGame, req.user.id), balance: freshUser.balance });
  } finally {
    _rematchLocks.delete(game.id);
  }
});

// ── Game Routes ───────────────────────────────────────────────────────────────
app.post('/api/game/start', requireAuth, gameLimiter, async (req, res) => {
  const existingPvp = await getPvpGameByUser(req.user.id);
  if (existingPvp && existingPvp.phase !== 'complete') {
    return res.status(400).json({ error: 'Terminez votre 1v1 avant une partie solo' });
  }
  const bet = parseInt(req.body?.bet);
  if (isNaN(bet) || bet < 10)  return res.status(400).json({ error: 'Mise minimum : 10 🥞' });
  if (bet > 999999999)           return res.status(400).json({ error: 'Mise maximum : 999 999 999 🥞' });

  const u = req.user;
  if (u.balance < bet) return res.status(400).json({ error: 'Solde insuffisant' });

  let bal;
  try { bal = await deductBalance(u.id, bet, { burnBonus: true }); } catch { return res.status(400).json({ error: 'Solde insuffisant' }); }

  const prev = await getGame(u.id);
  const shoe = prev ? (prev.shoe ?? createShoe()) : createShoe();

  const playerHand = [drawCard(shoe), drawCard(shoe)];
  const dealerHand = [drawCard(shoe), drawCard(shoe)];

  const gs = {
    shoe, hands: [playerHand], bets: [bet], dealerHand,
    phase: 'player_turn', activeHandIndex: 0, result: null,
  };

  if (isBlackjack(playerHand) || isBlackjack(dealerHand)) {
    gs.phase  = 'complete';
    gs.result = resolveGame(gs);
    bal = await addBalance(u.id, gs.result.totalWin) ?? bal;
    recordGameStats(u.id, gs);
  }

  await setGame(u.id, gs);
  res.json({ success: true, game: sanitize(gs), balance: bal });
});

app.post('/api/game/hit', requireAuth, gameLimiter, async (req, res) => {
  const gs = await getGame(req.user.id);
  if (!gs) return res.status(400).json({ error: 'Aucune partie en cours' });
  if (gs.phase !== 'player_turn') return res.status(400).json({ error: 'Action impossible' });

  const idx = gs.activeHandIndex;
  gs.hands[idx].push(drawCard(gs.shoe));

  const val = handValue(gs.hands[idx]);
  if (isBust(gs.hands[idx]) || val === 21) {
    if (idx < gs.hands.length - 1) gs.activeHandIndex++;
    else await _runDealer(gs, req.user.id);
  }

  await _save(req.user.id, gs, res, req.user.balance);
});

app.post('/api/game/stand', requireAuth, gameLimiter, async (req, res) => {
  const gs = await getGame(req.user.id);
  if (!gs) return res.status(400).json({ error: 'Aucune partie en cours' });
  if (gs.phase !== 'player_turn') return res.status(400).json({ error: 'Action impossible' });

  if (gs.activeHandIndex < gs.hands.length - 1) gs.activeHandIndex++;
  else await _runDealer(gs, req.user.id);

  await _save(req.user.id, gs, res, req.user.balance);
});

app.post('/api/game/double', requireAuth, gameLimiter, async (req, res) => {
  const gs  = await getGame(req.user.id);
  if (!gs) return res.status(400).json({ error: 'Aucune partie en cours' });
  const idx = gs.activeHandIndex;
  if (gs.phase !== 'player_turn' || gs.hands[idx].length !== 2)
    return res.status(400).json({ error: 'Double non disponible' });

  const u = req.user;
  const extra = gs.bets[idx];
  if (u.balance < extra) return res.status(400).json({ error: 'Solde insuffisant pour doubler' });

  try { await deductBalance(u.id, extra, { burnBonus: true }); } catch { return res.status(400).json({ error: 'Solde insuffisant pour doubler' }); }
  gs.bets[idx] *= 2;
  gs.hands[idx].push(drawCard(gs.shoe));
  getStats(u.id).doubles++;

  if (idx < gs.hands.length - 1) gs.activeHandIndex++;
  else await _runDealer(gs, req.user.id);

  await _save(req.user.id, gs, res, req.user.balance);
});

app.post('/api/game/split', requireAuth, gameLimiter, async (req, res) => {
  const gs   = await getGame(req.user.id);
  if (!gs) return res.status(400).json({ error: 'Aucune partie en cours' });
  const idx  = gs.activeHandIndex;
  const hand = gs.hands[idx];

  if (gs.phase !== 'player_turn' || hand.length !== 2 ||
      hand[0].rank !== hand[1].rank || gs.hands.length >= 4)
    return res.status(400).json({ error: 'Division non disponible' });

  const u = req.user;
  const splitBet = gs.bets[idx];
  if (u.balance < splitBet) return res.status(400).json({ error: 'Solde insuffisant pour diviser' });

  try { await deductBalance(u.id, splitBet, { burnBonus: true }); } catch { return res.status(400).json({ error: 'Solde insuffisant pour diviser' }); }
  const [c1, c2] = hand;
  gs.hands[idx] = [c1, drawCard(gs.shoe)];
  gs.hands.splice(idx + 1, 0, [c2, drawCard(gs.shoe)]);
  gs.bets.splice(idx + 1, 0, splitBet);
  getStats(u.id).splits++;

  await _save(req.user.id, gs, res, req.user.balance);
});

app.get('/api/game/state', requireAuth, async (req, res) => {
  const gs = await getGame(req.user.id);
  if (!gs) return res.json({ game: null });
  res.json({ game: sanitize(gs), balance: req.user.balance });
});

app.post('/api/game/clear', requireAuth, async (req, res) => {
  await deleteGame(req.user.id);
  res.json({ success: true });
});

// ── Helpers ───────────────────────────────────────────────────────────────────
async function _runDealer(gs, userId) {
  while (handValue(gs.dealerHand) < 17) gs.dealerHand.push(drawCard(gs.shoe));
  gs.phase  = 'complete';
  gs.result = resolveGame(gs);
  return gs.result.totalWin; // balance handled in _save via parallel calls
}

async function _save(userId, gs, res, balance) {
  // Run setGame and addBalance in parallel — they are independent
  const win = gs.phase === 'complete' && gs.result?.totalWin > 0 ? gs.result.totalWin : 0;
  const [, newBal] = await Promise.all([
    setGame(userId, gs),
    win > 0 ? addBalance(userId, win) : Promise.resolve(null),
  ]);
  const bal = newBal ?? balance ?? (await getUserById(userId, { fresh: true })).balance;
  // Record stats and broadcast leaderboard update when a game completes
  if (gs.phase === 'complete') {
    recordGameStats(userId, gs);
    _lbc.exp = 0; // bust the leaderboard cache
    for (const [, set] of _liveClients) {
      const body = `event: leaderboard:update\ndata: {}\n\n`;
      for (const r of set) { try { r.write(body); } catch {} }
    }
  }
  res.json({ success: true, game: sanitize(gs), balance: bal });
}

// ── Admin Routes ──────────────────────────────────────────────────────────────

// Change admin's own password
app.post('/api/admin/change-password', requireAdmin, adminLimiter, async (req, res) => {
  const { currentPassword, newPassword } = req.body ?? {};
  if (!currentPassword || !newPassword)
    return res.status(400).json({ error: 'Champs requis' });
  if (newPassword.length < 8)
    return res.status(400).json({ error: 'Nouveau mot de passe : 8 caractères minimum' });

  const user = await getUserByUsername(req.user.username);
  if (!user || !(await bcrypt.compare(currentPassword, user.password_hash)))
    return res.status(401).json({ error: 'Mot de passe actuel incorrect' });

  const hash = await bcrypt.hash(newPassword, 12);
  await supabase.from('users').update({ password_hash: hash }).eq('id', req.user.id);

  // Regenerate session after password change
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Erreur serveur' });
    req.session.userId = req.user.id;
    req.session.save((saveErr) => {
      if (saveErr) return res.status(500).json({ error: 'Erreur serveur' });
      console.log(`[ADMIN] ${req.user.username} → mot de passe admin changé`);
      res.json({ success: true });
    });
  });
});

// Check admin status (used by frontend)
app.get('/api/admin/me', requireAdmin, (req, res) => {
  res.json({ admin: true, username: req.user.username });
});

// List players with optional search
app.get('/api/admin/users', requireAdmin, adminLimiter, async (req, res) => {
  const search = (req.query.q || '').trim().slice(0, 50);
  let query = supabase
    .from('users')
    .select('id, username, balance, created_at, last_daily_claim, last_minigame_claim, is_admin')
    .eq('is_admin', false)
    .order('created_at', { ascending: false })
    .limit(100);

  if (search) query = query.ilike('username', `%${search}%`);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: 'Erreur serveur' });
  res.json({ users: data });
});

// Stats globales
app.get('/api/admin/stats', requireAdmin, adminLimiter, async (req, res) => {
  const { data: users } = await supabase
    .from('users').select('balance').eq('is_admin', false);
  const total  = users?.length ?? 0;
  const circ   = users?.reduce((s, u) => s + u.balance, 0) ?? 0;
  const { data: games } = await supabase.from('active_games').select('user_id');
  res.json({ totalPlayers: total, totalCirculation: circ, activeGames: games?.length ?? 0 });
});

// Modifier le solde
app.post('/api/admin/users/:id/balance', requireAdmin, adminLimiter, async (req, res) => {
  const { id } = req.params;
  const amount = parseInt(req.body?.amount);
  const action = req.body?.action; // 'add' | 'remove' | 'set'

  if (!['add', 'remove', 'set'].includes(action))
    return res.status(400).json({ error: 'Action invalide' });
  if (isNaN(amount) || amount < 0 || amount > 10_000_000)
    return res.status(400).json({ error: 'Montant invalide (0–10 000 000)' });

  const target = await getUserById(id);
  if (!target || target.is_admin) return res.status(404).json({ error: 'Joueur introuvable' });

  let newBalance;
  if (action === 'set') {
    const { data } = await supabase.from('users').update({ balance: amount }).eq('id', id).select('balance').single();
    newBalance = data.balance;
  } else if (action === 'add') {
    newBalance = await addBalance(id, amount);
  } else {
    // Atomic remove: uses deduct_balance, clamped to current balance to avoid error
    const { data: cur } = await supabase.from('users').select('balance').eq('id', id).single();
    const deduct = Math.min(amount, cur?.balance ?? 0);
    if (deduct > 0) {
      newBalance = await deductBalance(id, deduct);
    } else {
      newBalance = cur?.balance ?? 0;
    }
  }

  console.log(`[ADMIN] ${req.user.username} → balance ${action} ${amount} pour ${target.username} (nouveau: ${newBalance})`);
  res.json({ success: true, balance: newBalance });
});

// Changer le mot de passe d'un joueur
app.post('/api/admin/users/:id/password', requireAdmin, adminLimiter, async (req, res) => {
  const { id } = req.params;
  const { password } = req.body ?? {};

  if (!password || password.length < 6)
    return res.status(400).json({ error: 'Mot de passe : 6 caractères minimum' });

  const target = await getUserById(id);
  if (!target || target.is_admin) return res.status(404).json({ error: 'Joueur introuvable' });

  const hash = await bcrypt.hash(password, 12);
  await supabase.from('users').update({ password_hash: hash }).eq('id', id);

  console.log(`[ADMIN] ${req.user.username} → reset password pour ${target.username}`);
  res.json({ success: true });
});

// Changer le pseudo d'un joueur
app.post('/api/admin/users/:id/username', requireAdmin, adminLimiter, async (req, res) => {
  const { id } = req.params;
  const newName = (req.body?.username || '').trim();
  if (!newName) return res.status(400).json({ error: "Nom d'utilisateur requis" });
  if (newName.length < 3 || newName.length > 20)
    return res.status(400).json({ error: "Nom d'utilisateur : 3–20 caractères" });
  if (!/^[a-zA-Z0-9_]+$/.test(newName))
    return res.status(400).json({ error: "Lettres, chiffres et _ uniquement" });
  if (containsBannedWord(newName))
    return res.status(400).json({ error: "Ce nom d'utilisateur n'est pas autorisé" });

  const target = await getUserById(id);
  if (!target || target.is_admin) return res.status(404).json({ error: 'Joueur introuvable' });

  if (newName.toLowerCase() === target.username.toLowerCase())
    return res.status(400).json({ error: "C'est déjà son pseudo" });

  const existing = await getUserByUsername(newName);
  if (existing) return res.status(409).json({ error: "Ce nom d'utilisateur est déjà pris" });

  const { error } = await supabase.from('users').update({ username: newName }).eq('id', id);
  if (error) return res.status(500).json({ error: 'Erreur serveur' });

  _ucDel(id);
  _lbc.exp = 0;
  console.log(`[ADMIN] ${req.user.username} → renamed ${target.username} to ${newName}`);
  res.json({ success: true, username: newName });
});

// Réinitialiser le solde à 3000
app.post('/api/admin/users/:id/reset', requireAdmin, adminLimiter, async (req, res) => {
  const { id } = req.params;
  const target = await getUserById(id);
  if (!target || target.is_admin) return res.status(404).json({ error: 'Joueur introuvable' });

  await supabase.from('users').update({ balance: 3000, non_transferable: 3000 }).eq('id', id);
  await supabase.from('active_games').delete().eq('user_id', id);

  console.log(`[ADMIN] ${req.user.username} → reset compte de ${target.username}`);
  res.json({ success: true, balance: 3000 });
});

// Supprimer un joueur
app.delete('/api/admin/users/:id', requireAdmin, adminLimiter, async (req, res) => {
  const { id } = req.params;
  const target = await getUserById(id);
  if (!target || target.is_admin) return res.status(404).json({ error: 'Joueur introuvable' });

  await supabase.from('active_games').delete().eq('user_id', id);
  await supabase.from('users').delete().eq('id', id);

  console.log(`[ADMIN] ${req.user.username} → suppression de ${target.username}`);
  res.json({ success: true });
});

// ── Session cleanup — purge expired sessions every hour ───────────────────────
setInterval(async () => {
  await supabase.from('session').delete().lt('expire', new Date().toISOString());
}, 60 * 60 * 1000);

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Erreur serveur' });
});
process.on('unhandledRejection', (reason) => console.error('UnhandledRejection:', reason));

// ── Startup check ─────────────────────────────────────────────────────────────
async function checkDB() {
  const checks = await Promise.all([
    supabase.from('users').select('id').limit(1),
    supabase.from('friendships').select('user_id').limit(1),
    supabase.from('friend_requests').select('id').limit(1),
    supabase.from('pvp_invites').select('id').limit(1),
    supabase.from('pvp_games').select('id').limit(1),
  ]);
  if (checks.some(result => result.error)) {
    console.error('\n❌  Tables Supabase introuvables.');
    console.error('   → Exécute supabase_schema.sql dans le SQL Editor de ton projet Supabase.\n');
    process.exit(1);
  }

  const progressionCheck = await supabase.from('users').select('daily_streak,minigame_pity').limit(1);
  if (isMissingColumnError(progressionCheck.error)) {
    _progressionSchema.supported = false;
    console.warn('\n⚠️  Colonnes de progression absentes: users.daily_streak, users.minigame_pity');
    console.warn('   → Le jeu démarre en mode compatibilité. Exécute supabase_schema.sql pour activer les streaks et la progression spatule.\n');
  } else if (!progressionCheck.error) {
    _progressionSchema.supported = true;
  }
}

// ── Start ─────────────────────────────────────────────────────────────────────
checkDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🥞  Blackjack Crêpes  →  http://localhost:${PORT}\n`);
  });
});
