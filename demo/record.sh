#!/bin/bash
cd /Users/damienchedan/Documents/dev/perso/anon-pii

sleep 0.5
echo "$ echo \"SELECT * FROM crew WHERE email = 'jean.dupont@example-air.com' AND phone = '+33 6 12 34 56 78';\" | anon"
sleep 0.3
echo "SELECT * FROM crew WHERE email = 'jean.dupont@example-air.com' AND phone = '+33 6 12 34 56 78';" | anon
sleep 2

echo ""
echo '$ echo "..." | anon | claude -p "explain this query" | anon restore'
sleep 0.3
echo "SELECT * FROM crew WHERE email = 'jean.dupont@example-air.com' AND phone = '+33 6 12 34 56 78';" | anon | claude -p "explain this query" | anon restore
sleep 2
