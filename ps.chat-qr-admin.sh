#!/bin/bash
# ps.chat-qr-admin.sh - Gera QR code de uma sala existente (admin)

read -p "Token da sala: " TOKEN
URL="http://localhost:5000/sala/$TOKEN"
if command -v qrencode &>/dev/null; then
    qrencode -t ANSIUTF8 "$URL"
    echo "QR Code gerado. Escaneie com a câmera."
else
    echo "Instale qrencode: pkg install qrencode"
fi