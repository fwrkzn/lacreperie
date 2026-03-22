'use strict';
require('dotenv').config();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY, {
  auth: { persistSession: false }
});

function generatePassword() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  const specials = '!@#$%&*';
  let pwd = '';
  for (let i = 0; i < 12; i++) pwd += chars[crypto.randomInt(chars.length)];
  pwd += specials[crypto.randomInt(specials.length)];
  pwd += crypto.randomInt(10);
  // Shuffle
  return pwd.split('').sort(() => crypto.randomInt(3) - 1).join('');
}

async function main() {
  const password = generatePassword();
  const hash     = await bcrypt.hash(password, 12);

  const { data: existing } = await supabase
    .from('users').select('id').ilike('username', 'admin').maybeSingle();

  if (existing) {
    await supabase.from('users')
      .update({ password_hash: hash, is_admin: true, balance: 0 })
      .eq('id', existing.id);
    console.log('\n✅  Mot de passe admin réinitialisé.');
  } else {
    const { error } = await supabase.from('users').insert({
      username: 'admin',
      password_hash: hash,
      balance: 0,
      is_admin: true,
    });
    if (error) { console.error('Erreur:', error.message); process.exit(1); }
    console.log('\n✅  Compte admin créé.');
  }

  console.log('─────────────────────────────');
  console.log('  Identifiant : admin');
  console.log('  Mot de passe:', password);
  console.log('─────────────────────────────');
  console.log('⚠️  Note bien ce mot de passe, il ne sera plus affiché.\n');
}

main().catch(e => { console.error(e); process.exit(1); });
