#!/bin/bash

# Your source file
SOURCE="bot.c"

# List of architectures (based on your folders)
ARCHS=(arc i486 i586 i686 m68k mips mipsel powerpc sh4 sparc \
       armv4l armv5l armv6l armv7l powerpc-440fp x86_64)

echo "Starting build for: ${ARCHS[*]}"
echo

# Loop through each arch and compile
for arch in "${ARCHS[@]}"; do
    TOOLCHAIN="./$arch/bin"
    COMPILER=$(find "$TOOLCHAIN" -name "*-gcc" | head -n 1)

    if [[ -x "$COMPILER" ]]; then
        echo "Compiling for $arch using $COMPILER ..."
        "$COMPILER" -std=gnu99 -static -O2 -o "bot_$arch" "$SOURCE" -lpthread

        if [[ $? -eq 0 ]]; then
            echo "✅ Success: bot_$arch"
        else
            echo "❌ Failed: $arch"
        fi
    else
        echo "⚠️  Skipping $arch — compiler not found"
    fi
    echo
done
