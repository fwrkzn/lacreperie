# AI Context

## Project
- Name: `blackjack-crepes`
- Type: single-process Express app serving one large SPA from `public/index.html`
- Purpose: French blackjack game with virtual `🥞` currency, auth, gifts, daily bonus, spatula minigame, leaderboard, admin tools

## Runtime
- Entry: [server.js](/Users/furkan/Documents/claudeworkspace/4.blackjack/server.js)
- Frontend: [public/index.html](/Users/furkan/Documents/claudeworkspace/4.blackjack/public/index.html)
- Start: `npm start`
- Local dev port often used here: `8000`
- Deploy style: long-running Node process is preferred; latency is worse on serverless/serverless-like setups

## Main Files
- [server.js](/Users/furkan/Documents/claudeworkspace/4.blackjack/server.js): all backend routes, auth, sessions, balance/game logic, leaderboard, admin
- [public/index.html](/Users/furkan/Documents/claudeworkspace/4.blackjack/public/index.html): all HTML/CSS/JS for auth, lobby, leaderboard screen, blackjack screen
- [supabase_schema.sql](/Users/furkan/Documents/claudeworkspace/4.blackjack/supabase_schema.sql): schema + SQL RPCs
- [package.json](/Users/furkan/Documents/claudeworkspace/4.blackjack/package.json): no build step, plain Node

## Data / DB
- Backend uses Supabase via env vars `SUPABASE_URL`, `SUPABASE_KEY`
- Important tables:
  - `users`
  - `session`
  - `active_games`
- Important user columns:
  - `balance`
  - `non_transferable`
  - `last_daily_claim`
  - `last_minigame_claim`
  - `is_admin`
- Important RPCs:
  - `deduct_balance`
  - `add_balance`

## Key Rules
- Starter balance: `3000`
- `non_transferable` is used for starter gift + daily bonus + spatula reward
- Gifts/transfers can only use `balance - non_transferable`
- Daily bonus:
  - `2000`
  - once per server day, not rolling 24h
- Spatula minigame:
  - 2-minute cooldown
  - countdown uses server time responses
- Main bet input is clamped to current balance and game max (`50000`)

## Frontend Structure
- Screens:
  - `screen-auth`
  - `screen-lobby`
  - `screen-leaderboard`
  - `screen-game`
- Navigation is handled in JS with `transitionTo(...)`
- Lobby currently has:
  - full-width greeting
  - left info panels
  - center main actions
  - right compact leaderboard + button to full leaderboard page

## Important UX Changes Already Present
- Mobile auth keyboard should not auto-open; login fields are unlocked on tap
- Greeting is local-time based:
  - `Bonjour` from `04:00` to `16:59`
  - `Bonsoir` otherwise
- Enter on main bet input starts game
- Enter on replay bet input triggers replay
- Lobby has animated background ambience
- Main lobby uses an `ALL-IN` chip, not a separate button
- Replay area still has a red `All-in` button

## Leaderboard
- Compact leaderboard endpoint: `GET /api/leaderboard`
- Full leaderboard endpoint now uses: `GET /api/leaderboard?full=1`
- Server-side leaderboard cache exists and is invalidated on balance change

## Performance Notes
- App depends on session store + DB reads heavily
- `rolling: true` is still enabled in session config
- In-memory caches help only when process stays warm
- Remote lag is likely from Railway <-> Supabase latency plus many small requests

## Current Known State
- Worktree is dirty
- Current relevant modified files:
  - [public/index.html](/Users/furkan/Documents/claudeworkspace/4.blackjack/public/index.html)
  - [server.js](/Users/furkan/Documents/claudeworkspace/4.blackjack/server.js)
- Unrelated untracked files also exist:
  - `.DS_Store`
  - `.playwright-mcp/`
  - `LICENSE.txt`

## Good First Checks For Any Future AI
- Verify app locally: `PORT=8000 npm start`
- Verify server syntax: `node -c server.js`
- If leaderboard/gifts/session feel wrong, inspect:
  - session store logic in `server.js`
  - Supabase RPC signatures in `supabase_schema.sql`
  - client rendering logic in `public/index.html`
