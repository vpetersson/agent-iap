"""Authored from scratch on an 80x70 cell grid. Nothing here is derived from the raster."""
import math

W, H = 80, 74

PALETTE = {
    'N': '#001c44',   # navy
    'M': '#044ca4',   # mid blue, shading
    'B': '#0868d8',   # blue
    'K': '#0cccfc',   # bright cyan, highlights
    'S': '#58d8d8',   # cyan, the rule
    'C': '#24f4d8',   # mint, icon glyphs and the dial needle
    'L': '#e0f0f0',   # near white, the dial bezel
}

grid = [[None]*W for _ in range(H)]

def put(x, y, c):
    if 0 <= x < W and 0 <= y < H and c != '.':
        grid[y][x] = c

def rect(x0, y0, x1, y1, c):
    for y in range(y0, y1+1):
        for x in range(x0, x1+1):
            put(x, y, c)

def blit(x0, y0, rows):
    for dy, row in enumerate(rows):
        for dx, ch in enumerate(row):
            put(x0+dx, y0+dy, ch)

def outline(mask, c):
    """navy edge on the outside of a boolean mask"""
    out = set()
    for (x, y) in mask:
        for dx, dy in ((1,0),(-1,0),(0,1),(0,-1)):
            if (x+dx, y+dy) not in mask:
                out.add((x+dx, y+dy))
    for (x, y) in out:
        put(x, y, c)

# ---------------------------------------------------------------- shackle
CX = 39.5                      # every element is mirrored about this axis
SH_CY, SH_RO, SH_RI = 8.0, 8.0, 4.0
shackle = set()
for y in range(0, 19):
    for x in range(W):
        if y <= 8:
            d = math.hypot(x + 0.5 - CX, y + 0.5 - SH_CY)
            if SH_RI <= d <= SH_RO:
                shackle.add((x, y))
        else:
            if 32 <= x <= 35 or 44 <= x <= 47:
                shackle.add((x, y))
for (x, y) in shackle:
    put(x, y, 'B')
for (x, y) in sorted(shackle):
    d = math.hypot(x + 0.5 - CX, y + 0.5 - SH_CY)
    if y <= 8 and d >= SH_RO - 1.3 and x < CX:
        put(x, y, 'K')                      # highlight over the crown
    if y > 8 and x in (33, 34):
        put(x, y, 'K')                      # and down the left limb
outline(shackle, 'N')

# ---------------------------------------------------------------- lock body
BX0, BX1, BY0, BY1 = 24, 55, 16, 39
rect(BX0, BY0, BX1, BY1, 'N')
for x, y in ((BX0, BY0), (BX1, BY0), (BX0, BY1), (BX1, BY1)):
    grid[y][x] = None                       # notch the corners
rect(BX0+1, BY0+1, BX1-1, BY1-1, 'B')
rect(BX0+1, BY0+1, BX1-1, BY0+2, 'K')       # lid band
rect(BX0+1, BY0+3, BX1-1, BY0+3, 'S')
rect(BX0+1, BY0+4, BX1-1, BY0+4, 'N')       # seam under the lid
rect(BX1-2, BY0+5, BX1-1, BY1-1, 'M')       # shading down the right flank
rect(BX0+1, BY0+5, BX0+1, BY1-2, 'K')       # highlight up the left flank

# ---------------------------------------------------------------- dial
DCX, DCY = 39.5, 28.5
for y in range(BY0, BY1+1):
    for x in range(BX0, BX1+1):
        d = math.hypot(x + 0.5 - DCX, y + 0.5 - DCY)
        if d < 7.0:
            put(x, y, 'N')
        elif d < 8.6:
            put(x, y, 'L')
        elif d < 9.6:
            put(x, y, 'N')

# gauge: a needle from the hub out to the upper right, tick mark opposite
NEEDLE = [
    (39, 28), (40, 28), (39, 29), (40, 29),          # hub
    (40, 27), (41, 27), (41, 26), (42, 26),          # shaft
    (42, 25), (43, 25), (43, 24),
    (42, 23), (43, 23), (44, 24),                    # head
]
for (x, y) in NEEDLE:
    put(x, y, 'C')
rect(35, 26, 36, 27, 'C')                            # tick opposite the needle

# ---------------------------------------------------------------- shoulders
SY0, SY1 = 40, 48
for y in range(SY0, SY1+1):
    inset = max(0, SY0 + 2 - y)
    rect(22 + inset, y, 57 - inset, y, 'N')
for y in range(SY0, SY1-2):                 # collar: a blue crescent
    for x in range(26, 54):
        d = math.hypot(x + 0.5 - CX, y + 0.5 - (SY0 - 4.0))
        if 8.5 <= d <= 11.5:
            put(x, y, 'B')
blit(25, 43, ['KK..', '.KK.', '.KK.', '..KK', '..KK'])
blit(51, 43, ['..KK', '.KK.', '.KK.', 'KK..', 'KK..'])

# ---------------------------------------------------------------- node icons
FRAME_TOP = '.NNNNNNNNNNN.'
FRAME_MID = 'NNNNNNNNNNNNN'

def icon(glyph):
    rows = [FRAME_TOP, FRAME_MID] + list(glyph)
    while len(rows) < 11:
        rows.append(FRAME_MID)
    rows.append(FRAME_TOP)
    return rows

MONITOR = icon([
    'NNCCCCCCCCCNN',
    'NNCNNNNNNNCNN',
    'NNCNNNNNNNCNN',
    'NNCNNNNNNNCNN',
    'NNCCCCCCCCCNN',
    'NNNNNCCCNNNNN',
    'NNNCCCCCCCNNN',
])
SERVER = icon([
    'NNCCCCCCCCCNN',
    'NNCNCCCCCCCNN',
    'NNCCCCCCCCCNN',
    'NNNNNNNNNNNNN',
    'NNCCCCCCCCCNN',
    'NNCNCCCCCCCNN',
    'NNCCCCCCCCCNN',
])
GLOBE = icon([
    'NNNNCCCCNNNNN',
    'NNCCCCCCCCNNN',
    'NCCNNCCNNCCNN',
    'NCCNNCCNNCCNN',
    'NCCCCCCCCCCNN',
    'NCCNNCCNNCCNN',
    'NCCNNCCNNCCNN',
    'NNCCCCCCCCNNN',
    'NNNNCCCCNNNNN',
])
LAPTOP = icon([
    'NNNCCCCCCCNNN',
    'NNNCNNNNNCNNN',
    'NNNCNNNNNCNNN',
    'NNNCCCCCCCNNN',
    'NNCCCCCCCCCNN',
])

def mirror(rows):
    return [r[::-1] for r in rows]

blit(0,  9, MONITOR)
blit(0, 28, SERVER)
blit(67, 9, mirror(GLOBE))
blit(67, 28, mirror(LAPTOP))

# ---------------------------------------------------------------- connectors
def node(x, y):
    blit(x, y, ['.NN.', 'NNNN', 'NNNN', '.NN.'])
    rect(x+1, y+1, x+2, y+2, 'C')

def dashes(cells):
    for (x, y) in cells:
        put(x, y, 'N')

dashes([(14, 14), (15, 14)])                # upper left run
node(16, 13)
dashes([(20, 15), (21, 16), (22, 18), (23, 19)])
dashes([(14, 33), (15, 33)])                # lower left run
node(16, 32)
dashes([(20, 32), (21, 31), (22, 29), (23, 28)])

for y in range(0, 50):                      # mirror the runs into the right half
    for x in range(13, 24):
        c = grid[y][x]
        if c:
            put(W-1-x, y, c)

# ---------------------------------------------------------------- wordmark
WORD_TOP = 53          # cap line
RULE_Y = 72

def draw_wordmark():
    try:
        from glyphs import GLYPHS
    except Exception:
        return False
    text = [('A', 'N'), ('g', 'N'), ('e', 'N'), ('n', 'N'), ('t', 'N'),
            (' ', None),
            ('I', 'B'), ('A', 'B'), ('P', 'B')]
    widths = []
    for ch, _ in text:
        widths.append(4 if ch == ' ' else len(GLYPHS[ch][0]))
    total = sum(widths) + (len(text) - 1)          # 1 cell of letterspacing
    x = int(round(CX - total / 2.0))
    painted = []
    for (ch, colour), w in zip(text, widths):
        if ch != ' ':
            for dy, row in enumerate(GLYPHS[ch]):
                for dx, cell in enumerate(row):
                    if cell == '#':
                        put(x + dx, WORD_TOP + dy, colour)
                        if colour == 'N':
                            painted.append((x + dx, WORD_TOP + dy))
        x += w + 1
    return total, painted

# ---------------------------------------------------------------- rule
rect(6, RULE_Y, 32, RULE_Y + 1, 'S')
rect(47, RULE_Y, 73, RULE_Y + 1, 'S')
for dx in (35, 39, 43):
    rect(dx, RULE_Y, dx + 1, RULE_Y + 1, 'C')

# ---------------------------------------------------------------- render
def merged_rects():
    """greedy horizontal runs, then extend vertically while identical"""
    used = [[False]*W for _ in range(H)]
    out = []
    for y in range(H):
        x = 0
        while x < W:
            c = grid[y][x]
            if c is None or used[y][x]:
                x += 1; continue
            x2 = x
            while x2+1 < W and grid[y][x2+1] == c and not used[y][x2+1]:
                x2 += 1
            y2 = y
            while y2+1 < H and all(grid[y2+1][i] == c and not used[y2+1][i] for i in range(x, x2+1)):
                y2 += 1
            for yy in range(y, y2+1):
                for xx in range(x, x2+1):
                    used[yy][xx] = True
            out.append((x, y, x2-x+1, y2-y+1, c))
            x = x2+1
    return out

def to_svg(x0, y0, x1, y1, path):
    rs = [r for r in merged_rects()]
    w, h = x1-x0+1, y1-y0+1
    by_colour = {}
    for (x, y, rw, rh, c) in rs:
        if x+rw <= x0 or x > x1 or y+rh <= y0 or y > y1:
            continue
        by_colour.setdefault(c, []).append((x-x0, y-y0, rw, rh))
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" shape-rendering="crispEdges">']
    for c in sorted(by_colour):
        d = ''.join(f'M{x} {y}h{rw}v{rh}h{-rw}z' for (x, y, rw, rh) in by_colour[c])
        parts.append(f'  <path fill="{PALETTE[c]}" d="{d}"/>')
    parts.append('</svg>')
    open(path, 'w').write('\n'.join(parts) + '\n')
    return len(by_colour), sum(len(v) for v in by_colour.values())

def to_png(path, bg, zoom=8):
    from PIL import Image
    im = Image.new('RGB', (W, H), bg)
    px = im.load()
    for y in range(H):
        for x in range(W):
            c = grid[y][x]
            if c:
                px[x, y] = tuple(int(PALETTE[c][i:i+2], 16) for i in (1, 3, 5))
    im.resize((W*zoom, H*zoom), Image.NEAREST).save(path)

def bbox():
    xs = [x for y in range(H) for x in range(W) if grid[y][x]]
    ys = [y for y in range(H) for x in range(W) if grid[y][x]]
    return min(xs), min(ys), max(xs), max(ys)

def square_box(x0, y0, x1, y1):
    w, h = x1 - x0 + 1, y1 - y0 + 1
    side = max(w, h)
    return (x0 - (side - w)//2, y0 - (side - h)//2,
            x0 - (side - w)//2 + side - 1, y0 - (side - h)//2 + side - 1)

if __name__ == '__main__':
    total, word_cells = draw_wordmark()

    x0, y0, x1, y1 = bbox()
    n, r = to_svg(x0, y0, x1, y1, 'logo.svg')
    print(f'logo.svg       {x1-x0+1}x{y1-y0+1} cells, {n} colours, {r} rects')
    to_png('proof-light.png', '#ffffff')

    # the mark alone, on a square field
    MARK_LAST = 48
    below = {(x, y): grid[y][x] for y in range(MARK_LAST+1, H) for x in range(W) if grid[y][x]}
    for (x, y) in below:
        grid[y][x] = None
    xs = [x for y in range(MARK_LAST+1) for x in range(W) if grid[y][x]]
    ys = [y for y in range(MARK_LAST+1) for x in range(W) if grid[y][x]]
    n, r = to_svg(*square_box(min(xs), min(ys), max(xs), max(ys)), 'icon.svg')
    print(f'icon.svg       square, {n} colours, {r} rects')
    for (x, y), c in below.items():
        grid[y][x] = c

    # dark variant: the only change is the wordmark, which is navy on navy
    for (x, y) in word_cells:
        grid[y][x] = 'L'
    n, r = to_svg(x0, y0, x1, y1, 'logo-dark.svg')
    print(f'logo-dark.svg  {x1-x0+1}x{y1-y0+1} cells, {n} colours, {r} rects')
    to_png('proof-dark.png', '#0d1117')
