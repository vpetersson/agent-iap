## Logo

`logo-original.png` is the artwork as delivered — 1254×1254, the full lockup
centred on its cream field. It is the master; re-crop from it, not from the
files below.

The two derivatives are what the project actually uses:

| File | Size | Use |
| --- | --- | --- |
| `logo.png` | 1062×943 | The full lockup — mark and wordmark. README header, docs, slides. |
| `icon.png` | 1062×1062 | The mark alone, squared. Repo avatar, social preview, favicon source. |

Both are cropped to the ink with a 48px margin, flattened onto a flat
`#fbf9f5` (the master's background carries a little generation noise), and
saved as a 64-colour palette PNG. The background is part of the artwork: the
navy in the mark has no contrast against a dark page, so these are not
transparent and should not be made transparent.

Regenerating a derivative after the master changes is a crop-plus-quantise, and
the numbers above are the whole recipe.
