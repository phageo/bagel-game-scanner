# Icon sources

The two pictures `tools/build_icon.py` makes `gamescan/bagel.ico` from:

    python tools/build_icon.py --inputs assets/icon

| File | Gives the sizes |
| --- | --- |
| `bagel_pixel.png` | 16, 24, 32 (cut to the drawing, nearest neighbour) |
| `bagel_ai.png` | 48, 64, 128, 256 (black background removed, shrunk by area) |

Both hold only their picture chunks (IHDR, IDAT, IEND): no text, time, colour profile or other
metadata chunk (`python tools/export_source.py --strip <file>`; the export refuses a picture with
metadata, and line 13 of the release checklist checks the package's). The icon built from these
files is byte for byte `gamescan/bagel.ico`. The builder also writes `bagel_256_clean.png` here
(the cleaned 256 picture, for a look); it is not committed.
