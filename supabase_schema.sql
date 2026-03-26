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
CREATE OR REPLACE FUNCTION add_balance(p_user_id UUID, p_amount INTEGER)
RETURNS INTEGER AS $$
DECLARE
  v_new_balance INTEGER;
BEGIN
  UPDATE users
    SET balance = balance + p_amount
    WHERE id = p_user_id
    RETURNING balance INTO v_new_balance;

  RETURN v_new_balance;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
