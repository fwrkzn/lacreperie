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

// ── Supabase ──────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY,
  { auth: { persistSession: false } }
);

// ── Session secret ────────────────────────────────────────────────────────────
const DATA_DIR    = path.join(__dirname, 'data');
const SECRET_FILE = path.join(DATA_DIR, 'secret.key');
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
  constructor() { super(); this._mem = new Map(); }

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
  rolling: true,
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
app.use(globalLimiter);

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

// ── User cache (10s TTL — avoids repeated DB lookups per request) ─────────────
const _uc = new Map();
function _ucGet(id)       { const e = _uc.get(id); return (e && e.exp > Date.now()) ? e.d : null; }
function _ucSet(id, data) { _uc.set(id, { d: data, exp: Date.now() + 60_000 }); }
function _ucDel(id)       { _uc.delete(id); }

// ── DB helpers ────────────────────────────────────────────────────────────────
async function getUserByUsername(username) {
  const { data } = await supabase
    .from('users')
    .select('id, username, balance, non_transferable, password_hash, is_admin')
    .ilike('username', username)
    .maybeSingle();
  return data;
}

async function getUserById(id, { fresh = false } = {}) {
  if (!fresh) { const c = _ucGet(id); if (c) return c; }
  const { data } = await supabase
    .from('users')
    .select('id, username, balance, non_transferable, last_daily_claim, last_minigame_claim, is_admin')
    .eq('id', id)
    .maybeSingle();
  if (data) _ucSet(id, data);
  return data;
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

app.post('/api/heartbeat', requireAuth, (req, res) => {
  _online.set(req.user.id, Date.now());
  res.json({ ok: true });
});

function isOnline(userId) {
  const ts = _online.get(userId);
  return ts && (Date.now() - ts) < ONLINE_TIMEOUT;
}

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
      res.json({ success: true, user: { id: user.id, username: user.username, balance: user.balance, nonTransferable: user.non_transferable || 0 } });
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
    res.json({ success: true, user: { id: user.id, username: user.username, balance: user.balance, nonTransferable: user.non_transferable || 0 } });
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
      ...cooldowns,
    }
  });
}
app.get('/api/auth/me',  requireAuth, respondMe);
app.get('/api/user/me',  requireAuth, respondMe);

app.post('/api/user/daily-bonus', requireAuth, async (req, res) => {
  const now = getNowSeconds();
  const startOfToday = getStartOfServerDaySeconds(new Date(now * 1000));

  // Atomic: update only succeeds if the last claim is before today's server date.
  const { data } = await supabase.from('users')
    .update({ last_daily_claim: now })
    .eq('id', req.user.id)
    .or(`last_daily_claim.is.null,last_daily_claim.lt.${startOfToday}`)
    .select('last_daily_claim').maybeSingle();

  if (!data) {
    const cooldown = getDailyCooldownSeconds(req.user.last_daily_claim, now);
    return res.status(429).json({
      error: 'Bonus déjà réclamé aujourd’hui',
      serverNow: now,
      cooldown,
      availableAt: now + cooldown,
    });
  }
  const newBal = await addBalance(req.user.id, 2000, { nonTransferable: 2000 });
  const cooldown = getDailyCooldownSeconds(now, now);
  res.json({
    success: true,
    bonus: 2000,
    balance: newBal,
    serverNow: now,
    cooldown,
    availableAt: now + cooldown,
  });
});

app.post('/api/user/minigame', requireAuth, async (req, res) => {
  const now = getNowSeconds();
  // Atomic: update only succeeds if cooldown has passed — prevents double-claim race condition
  const { data } = await supabase.from('users')
    .update({ last_minigame_claim: now })
    .eq('id', req.user.id)
    .lt('last_minigame_claim', now - 120)
    .select('last_minigame_claim').maybeSingle();

  if (!data) {
    const cooldown = getMinigameCooldownSeconds(req.user.last_minigame_claim, now);
    return res.status(429).json({
      error: 'Spatule en recharge',
      serverNow: now,
      cooldown,
      availableAt: now + cooldown,
    });
  }
  const roll = Math.random();
  let reward;
  if      (roll < 0.70) reward = 30   + Math.floor(Math.random() * 71);
  else if (roll < 0.95) reward = 101  + Math.floor(Math.random() * 900);
  else                  reward = 1001 + Math.floor(Math.random() * 4000);

  const newBal = await addBalance(req.user.id, reward, { nonTransferable: reward });
  const cooldown = getMinigameCooldownSeconds(now, now);
  res.json({
    success: true,
    reward,
    balance: newBal,
    serverNow: now,
    cooldown,
    availableAt: now + cooldown,
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

app.get('/api/leaderboard', requireAuth, async (req, res) => {
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
  const me = myRank > 0 && myRank > 10
    ? { rank: myRank, username: req.user.username, balance: req.user.balance, isMe: true, online: true }
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
  if (amt > 50000)
    return res.status(400).json({ error: 'Montant maximum : 50 000 🥞' });

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
    _lbc.exp = 0; // invalidate leaderboard cache
    res.json({ success: true, balance: newBal });
  } catch(e) {
    res.status(400).json({ error: e.error || 'Erreur lors du transfert' });
  }
});

// ── Game Routes ───────────────────────────────────────────────────────────────
app.post('/api/game/start', requireAuth, gameLimiter, async (req, res) => {
  const bet = parseInt(req.body?.bet);
  if (isNaN(bet) || bet < 10)  return res.status(400).json({ error: 'Mise minimum : 10 🥞' });
  if (bet > 50000)              return res.status(400).json({ error: 'Mise maximum : 50 000 🥞' });

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
    console.log(`[ADMIN] ${req.user.username} → mot de passe admin changé`);
    res.json({ success: true });
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
  const { error } = await supabase.from('users').select('id').limit(1);
  if (error) {
    console.error('\n❌  Tables Supabase introuvables.');
    console.error('   → Exécute supabase_schema.sql dans le SQL Editor de ton projet Supabase.\n');
    process.exit(1);
  }
}

// ── Start ─────────────────────────────────────────────────────────────────────
checkDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🥞  Blackjack Crêpes  →  http://localhost:${PORT}\n`);
  });
});
