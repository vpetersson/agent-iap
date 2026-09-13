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

The SVGs are not a trace of the raster — a trace just re-encodes the raster's
grain. They are a rebuild. The source is pixel-art *styled* but it is not drawn
on a pixel grid: fitting a lattice to its edges gives a circular concentration
of 0.36 with residuals of 2-3px on a 12px period, cut spacings spread evenly
over 8-18px with no mode, and the wordmark's apparent step (~18px) differs from
the mark's (~12px). So the rebuild works in two stages. First the artwork is
reduced to the seven flat colours a designer would have picked, with the
antialiasing, the drop shadow, the inner bevels and the navy gradient all
resolved into whichever real colour they were sitting between — those are raster
decoration, and on a transparent background they read as grey grime. Then each
colour region's boundary is regularised to the artwork's own step size (12px
across the mark's silhouette, 4px over the node icons, the connectors and the
wordmark, where the source edges are already clean) and polygonised on pixel
boundaries, so every segment comes out horizontal or vertical with long runs
instead of 1px jitter.

The palette is exactly `#001c44`, `#044ca4`, `#0868d8`, `#0cccfc`, `#24f4d8`,
`#58d8d8` and `#e0f0f0`. Plain `<path fill="#rrggbb">` only: no filters, no
gradients, no embedded raster, no fonts, nothing that renders differently
between one SVG engine and the next — rsvg and cairosvg render them
pixel-identically.

Three properties worth checking if these are ever regenerated. No fill may be a
desaturated grey — a grey means an antialiasing blend or a shadow survived
classification, and it reads as a halo the moment the logo lands on a dark
background. Every path segment must be horizontal or vertical, with a median run
length in the neighbourhood of the artwork's step size rather than 1px. And the
features that every failed attempt has destroyed are the globe's grid, the
server's bars, the dial needle, and the "I" of IAP, whose serif bars vanish the
moment the wordmark is snapped to a lattice — check those four by eye.
