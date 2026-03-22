#!/bin/bash
cd "$(dirname "$0")"
if [ ! -d "node_modules" ]; then
  echo "📦 Installation des dépendances..."
  npm install
fi
echo "🥞 Lancement du serveur..."
node server.js
