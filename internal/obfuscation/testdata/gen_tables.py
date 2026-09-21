"""Writes ../scripts.tsv and ../confusables.tsv from the pinned confusable-homoglyphs package.

scripts.tsv is categories.json's code_points_ranges (start, end, ISO 15924 alias, hex);
confusables.tsv replicates skill_xray.checks.obfuscation._load_confusables: for every key that
is one non-ASCII code point, the first homoglyph that is a single ASCII letter.

    python internal/obfuscation/testdata/gen_tables.py
"""
import os

from confusable_homoglyphs._version import get_versions
from confusable_homoglyphs.categories import categories_data
from confusable_homoglyphs.confusables import confusables_data

here = os.path.dirname(os.path.abspath(__file__))
version = get_versions()["version"]
assert version == "3.3.1", version
header = "# confusable-homoglyphs %s\n" % version

aliases = categories_data["iso_15924_aliases"]
ranges = categories_data["code_points_ranges"]
assert len(ranges) == 2193, len(ranges)
with open(os.path.join(here, "..", "scripts.tsv"), "w", encoding="ascii", newline="\n") as f:
    f.write(header)
    for lo, hi, a, _category in ranges:
        f.write("%X\t%X\t%s\n" % (lo, hi, aliases[a]))

table = {}
for ch, homos in confusables_data.items():
    if len(ch) != 1 or ord(ch) <= 0x7F:
        continue
    for h in homos:
        t = h["c"] if isinstance(h, dict) else h
        if isinstance(t, str) and len(t) == 1 and t.isascii() and t.isalpha():
            table[ch] = t
            break
assert len(table) == 1225, len(table)
with open(os.path.join(here, "..", "confusables.tsv"), "w", encoding="ascii", newline="\n") as f:
    f.write(header)
    for ch, t in table.items():
        f.write("%X\t%s\n" % (ord(ch), t))
