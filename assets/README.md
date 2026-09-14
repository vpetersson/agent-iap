## Logo

`logo-original.png` is the artwork as first delivered — 1254×1254 on a cream
field. It is the reference for the design, not the source of the files below.

| File | Background | Use |
| --- | --- | --- |
| `logo.svg` | transparent | Full lockup. The README header on a light page. |
| `logo-dark.svg` | transparent | Same lockup, wordmark in `#e0f0f0`. Dark pages. |
| `icon.svg` | transparent | The mark alone, square. Avatar, social preview, favicon. Reads on any background. |
| `logo.png`, `icon.png` | cream `#fbf9f5` | Raster fallbacks, cropped from the original artwork. |

### The SVGs are drawn, not traced

`src/build.py` and `src/glyphs.py` are the source; the SVGs are its output.
Running `python3 build.py` regenerates all three.

This matters because the original is pixel-art *styled* but is not drawn on a
pixel grid, so nothing can recover one from it. Fitting a lattice to its edges
gives a circular concentration of 0.36 with 2-3px residuals on a 12px period;
within-cell variance falls monotonically from N=60 to N=160 with no minimum;
cut spacings spread evenly over 8-18px with no mode; and the wordmark's apparent
step (~18px) is not the mark's (~12px). Every attempt to derive a clean vector
from it either kept the raster's grain — antialiasing and drop shadow surviving
as grey outlines — or snapped it to a lattice that ate the small features.

So the artwork was redrawn on a real 80×74 grid, cell by cell: the padlock,
shackle, dial, shoulders, the four node icons, the dotted connectors, and a
purpose-built pixel face for "Agent IAP" with a 12-row cap height and 2-cell
stems. The palette is exactly `#001c44`, `#044ca4`, `#0868d8`, `#0cccfc`,
`#24f4d8`, `#58d8d8` and `#e0f0f0`.

Everything is integer `<path>` rectangles with `shape-rendering="crispEdges"`,
so there is no antialiasing anywhere — every rendered pixel is either fully
opaque or fully transparent, and rsvg and cairosvg produce byte-identical
rasters. Each file is about 5 KB.

### Editing

Edit `src/build.py`, not the SVGs. `build.py` also writes `proof-light.png` and
`proof-dark.png`, which are the grid rendered at 8× — look at those rather than
at the SVG source. The wordmark lives in `src/glyphs.py` as ASCII bitmaps, one
string per row, `#` for ink.

Two things to keep true if you change it. The dark variant exists because the
wordmark is `#001c44` navy: 18:1 against a white page, 1.03:1 against GitHub's
dark one, which is why `logo.svg` alone is not enough. And the features that
every earlier attempt destroyed are the globe's grid, the server's bars, the
dial needle and the serif bars on the "I" of IAP — check those four by eye.
