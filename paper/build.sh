#!/bin/sh
# Build the submission paper.
# Preferred: tectonic (single binary, fetches packages on demand).
# Any TeX Live installation works too:   latexmk -pdf main.tex
set -e
cd "$(dirname "$0")"
if command -v tectonic >/dev/null 2>&1; then
    exec tectonic main.tex
elif command -v latexmk >/dev/null 2>&1; then
    exec latexmk -pdf main.tex
else
    echo "No TeX engine found: install tectonic or texlive-latex-extra." >&2
    exit 1
fi
