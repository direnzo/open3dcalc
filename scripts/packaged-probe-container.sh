#!/usr/bin/env bash
#
# Container entry point for the W6 packaged keyring probe.
#
# A bare distro image has none of the shared libraries the packaged Electron
# runtime links against, so the probe would die in the dynamic loader with
# "error while loading shared libraries" — a failure that says nothing about the
# keyring gate. This installs what the loader needs, then execs the probe.
#
# BEST-EFFORT BY DESIGN, and deliberately so: package names move between
# releases (Ubuntu noble renamed libgtk-3-0 to libgtk-3-0t64, libasound2 to
# libasound2t64), and a single hardcoded list would be wrong on at least one of
# the three images. Each candidate is attempted on its own and a miss is not
# fatal. The real signal stays where it belongs: if the loader still cannot
# resolve a library, the probe fails loudly and the job reports it.
#
# Usage: bash packaged-probe-container.sh <packaged-probe-binary> [args...]

set -u

install_apt() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1 || true
  for pkg in "$@"; do
    apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1 || true
  done
}

install_dnf() {
  for pkg in "$@"; do
    dnf install -y --setopt=install_weak_deps=False "$pkg" >/dev/null 2>&1 || true
  done
}

if command -v apt-get >/dev/null 2>&1; then
  install_apt \
    libgtk-3-0t64 libgtk-3-0 \
    libnss3 libnspr4 \
    libasound2t64 libasound2 \
    libgbm1 libdrm2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxrandr2 libxtst6 libxss1 libxshmfence1 \
    libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libpango-1.0-0 libcairo2 libglib2.0-0 libgl1 \
    fonts-liberation
elif command -v dnf >/dev/null 2>&1; then
  install_dnf \
    gtk3 \
    nss nspr \
    alsa-lib \
    mesa-libgbm libdrm libxkbcommon \
    libXcomposite libXdamage libXrandr libXtst libXScrnSaver libxshmfence \
    atk at-spi2-atk cups-libs \
    pango cairo glib2 mesa-libGL \
    liberation-fonts
else
  echo "[packaged-probe] no known package manager; running the probe as-is" >&2
fi

exec "$@"
