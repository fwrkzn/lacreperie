-- ── Schéma Blackjack Crêpes ──────────────────────────────────────────────────
-- Coller dans : Supabase Dashboard → SQL Editor → New query → Run

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username            TEXT NOT NULL,
  password_hash       TEXT NOT NULL,
  balance             INTEGER NOT NULL DEFAULT 3000,
  non_transferable    INTEGER NOT NULL DEFAULT 3000,
  last_daily_claim    BIGINT NOT NULL DEFAULT 0,
  last_minigame_claim BIGINT NOT NULL DEFAULT 0,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower ON users (LOWER(username));

CREATE TABLE IF NOT EXISTS active_games (
  user_id    UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  game_state JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS friendships (
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  friend_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, friend_id),
  CHECK (user_id <> friend_id)
);

CREATE INDEX IF NOT EXISTS friendships_friend_id_idx ON friendships (friend_id);

CREATE TABLE IF NOT EXISTS friend_requests (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  from_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status       TEXT NOT NULL DEFAULT 'pending',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (from_user_id <> to_user_id)
);

CREATE INDEX IF NOT EXISTS friend_requests_from_idx ON friend_requests (from_user_id);
CREATE INDEX IF NOT EXISTS friend_requests_to_idx ON friend_requests (to_user_id);
CREATE INDEX IF NOT EXISTS friend_requests_status_idx ON friend_requests (status);

CREATE TABLE IF NOT EXISTS pvp_games (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  player_one_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  player_two_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status        TEXT NOT NULL DEFAULT 'active',
  game_state    JSONB NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (player_one_id <> player_two_id)
);

CREATE INDEX IF NOT EXISTS pvp_games_player_one_idx ON pvp_games (player_one_id);
CREATE INDEX IF NOT EXISTS pvp_games_player_two_idx ON pvp_games (player_two_id);
CREATE INDEX IF NOT EXISTS pvp_games_status_idx ON pvp_games (status);

CREATE TABLE IF NOT EXISTS pvp_invites (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  from_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount       INTEGER NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending',
  game_id      UUID REFERENCES pvp_games(id) ON DELETE SET NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (from_user_id <> to_user_id),
  CHECK (amount >= 10)
);

CREATE INDEX IF NOT EXISTS pvp_invites_from_idx ON pvp_invites (from_user_id);
CREATE INDEX IF NOT EXISTS pvp_invites_to_idx ON pvp_invites (to_user_id);
CREATE INDEX IF NOT EXISTS pvp_invites_status_idx ON pvp_invites (status);

CREATE TABLE IF NOT EXISTS gift_log (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  from_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount       INTEGER NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (from_user_id <> to_user_id),
  CHECK (amount >= 1)
);

CREATE INDEX IF NOT EXISTS gift_log_to_user_idx ON gift_log (to_user_id, created_at DESC);

-- ── Fonctions atomiques (évitent la race condition sur le solde) ───────────────

-- Déduit un montant du solde, échoue si insuffisant
-- p_burn_bonus = true → réduit aussi non_transferable (pour les mises de jeu)
CREATE OR REPLACE FUNCTION deduct_balance(p_user_id UUID, p_amount INTEGER, p_burn_bonus BOOLEAN DEFAULT FALSE)
RETURNS INTEGER AS $$
DECLARE
  v_new_balance INTEGER;
BEGIN
  IF p_burn_bonus THEN
    UPDATE users
      SET balance = balance - p_amount,
          non_transferable = GREATEST(0, non_transferable - p_amount)
      WHERE id = p_user_id AND balance >= p_amount
      RETURNING balance INTO v_new_balance;
  ELSE
    UPDATE users
      SET balance = balance - p_amount
      WHERE id = p_user_id AND balance >= p_amount
      RETURNING balance INTO v_new_balance;
  END IF;

  IF v_new_balance IS NULL THEN
    RAISE EXCEPTION 'Solde insuffisant';
  END IF;

  RETURN v_new_balance;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Ajoute un montant au solde
-- p_non_transferable > 0 → ajoute aussi ce montant au compteur non transférable
CREATE OR REPLACE FUNCTION add_balance(
  p_user_id UUID,
  p_amount INTEGER,
  p_non_transferable INTEGER DEFAULT 0
)
RETURNS INTEGER AS $$
DECLARE
  v_new_balance INTEGER;
BEGIN
  UPDATE users
    SET balance = balance + p_amount,
        non_transferable = non_transferable + GREATEST(0, p_non_transferable)
    WHERE id = p_user_id
    RETURNING balance INTO v_new_balance;

  RETURN v_new_balance;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
