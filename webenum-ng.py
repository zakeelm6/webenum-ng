#!/usr/bin/env python3
"""Wrapper clone-and-run : permet ./webenum-ng.py sans installation.

Le code vit dans le module importable webenum_ng (meme dossier).
Une fois installe via pip, utilise plutot la commande `webenum-ng`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from webenum_ng import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
