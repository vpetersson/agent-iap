## Logo

`logo-original.png` is the artwork as delivered — 1254×1254, the full lockup
centred on its cream field. It is the master; re-derive from it, not from the
files below.

| File | Size | Background | Use |
| --- | --- | --- | --- |
| `logo.png` | 1062×943 | cream `#fbf9f5` | Full lockup — mark and wordmark. The README header. |
| `icon.png` | 1062×1062 | cream `#fbf9f5` | The mark alone, squared. Repo avatar, social preview, favicon source. |
| `logo.svg` | vector | transparent | Full lockup, on a light surface. |
| `icon.svg` | vector | transparent | The mark alone, squared. Safe on any surface. |

### Which one to reach for

Use a PNG when the surface might be dark. The wordmark is `#011139` navy: on a
white page that is 18:1, on GitHub's dark page it is **1.03:1** — invisible.
The cream field is not decoration, it is what keeps the wordmark readable, so
`logo.png` is the one the README header uses and the safe default anywhere the
background is out of your control.

`icon.svg` has no such problem — the mark is bright blue and cyan throughout,
and it reads on white and on near-black alike. It is the right asset for a
favicon, a dark docs theme, or anywhere it needs to scale.

### How they were made

The PNGs are cropped to the ink with a 48px margin, flattened onto a flat
`#fbf9f5` (the master's field carries a little generation noise) and saved as
64-colour palette PNGs.

The SVGs are a per-colour contour trace of the same master: background found by
colour distance to the cream — under 15 is background, including the enclosed
holes like the shackle opening and the letter counters — ink quantised to 18
colours, each colour's mask traced with `potrace --alphamax 0 --opttolerance 0`
so edges stay polygonal, and each mask grown a pixel before tracing so adjacent
colours cannot leave a hairline crack between them. Plain `<path fill="#rrggbb">`
only: no filters, no gradients, no embedded raster, no fonts, nothing that
renders differently between one SVG engine and the next.

Two properties worth preserving if these are ever regenerated: no boundary pixel
of the artwork may be light — an antialiasing blend toward the cream, promoted
to its own pale ink colour, shows up as a halo the moment the logo lands on a
dark background — and adjacent colour regions must not separate into hairline
seams.
