import os, tempfile
TMP = tempfile.gettempdir()
import sys, io, time, random, struct, bisect, types
from PIL import Image, ImageFile
ImageFile.MAXBLOCK = 1 << 26
mod = types.ModuleType("jf"); mod.struct = struct; mod.time = time; mod.bisect = bisect
exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reflota.py")).read(), mod.__dict__)
U = 4096
class Src:
    def __init__(self, d): self.d = d
    def read(self, off, n): return bytes(self.d[off:off + n]).ljust(n, b"\0") if off < len(self.d) else b""
def foto(w, h, sem, sub):
    r = random.Random(sem); im = Image.new("RGB", (w, h)); px = im.load()
    f1, f2 = r.randint(1, 5), r.randint(1, 5)
    for y in range(h):
        for x in range(w):
            px[x, y] = ((x * f1 + y) % 256 ^ r.getrandbits(4), (x + y * f2) % 256 ^ r.getrandbits(3), (x * y // 5 + sem) % 256)
    b = io.BytesIO(); im.save(b, "JPEG", quality=r.choice([60, 85, 92]), subsampling=sub, optimize=r.random() < .4); return b.getvalue()
ok = tot = 0; tmax = 0; fallos = []
import os
SEMS = [int(x) for x in os.environ.get('SEMS','').split(',') if x] or range(24)
for sem in SEMS:
    rg = random.Random(1000 + sem)
    w, h = rg.choice([(480, 360), (800, 600), (1024, 768), (1600, 1200)])
    sub = rg.choice([0, 1, 2])
    jpg = foto(w, h, sem, sub)
    P = jpg + bytes(-len(jpg) % U); trozos = [P[i:i + U] for i in range(0, len(P), U)]
    nfrag = rg.choice([2, 2, 2, 3, 4])
    if len(trozos) < nfrag * 3: continue
    cortes = sorted(rg.sample(range(2, len(trozos) - 1), nfrag - 1))
    d = bytearray(); d += bytes(rg.getrandbits(8) for _ in range(3 * U)); a = len(d)
    k = 0; huecos = []
    for c in cortes + [len(trozos)]:
        for t in trozos[k:c]: d += t
        k = c
        if c != len(trozos):
            g = rg.choice([1, 2, 5, 20, 100, 300]); huecos.append(g)
            dec = rg.random() < .35; huecos[-1] = (g, 'decoy' if dec else 'ruido')
            if dec:      # relleno = datos de otro JPEG
                o = foto(w, h, sem + 500, sub); op = o + bytes(-len(o) % U); d += (op * 20)[U:U + g * U]
            else:
                d += bytes(rg.getrandbits(8) for _ in range(g * U))
    d += bytes(rg.getrandbits(8) for _ in range(10 * U))
    t = time.time(); r = mod.reconstruir_jpeg(Src(bytes(d)), a, len(d), U, tiempo=60); dt = time.time() - t
    rec = b"".join(bytes(d[o:o + l]) for o, l in r["frags"]) if r else None
    good = rec == jpg
    tot += 1; ok += good; tmax = max(tmax, dt)
    print(f"{'OK  ' if good else ('NONE' if not r else 'MAL ')} {w}x{h} sub={sub} {len(jpg)//1024}KB frags={nfrag} huecos={huecos} {dt:.1f}s")
    if not good: fallos.append((sem, w, h, sub, nfrag, huecos))
print(f"\n{ok}/{tot} reconstruidos idénticos; tiempo máx {tmax:.1f}s")
