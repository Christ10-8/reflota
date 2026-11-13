import os, tempfile
TMP = tempfile.gettempdir()
"""carve() con reconstruccion: disco FAT-like con fotos fragmentadas + archivos sanos; luego extraccion por CarveVolume."""
import sys, io, os, random, hashlib, importlib.util, time
from PIL import Image, ImageFile
ImageFile.MAXBLOCK = 1 << 26
spec = importlib.util.spec_from_file_location("reflota", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reflota.py"))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
random.seed(8)
U = 4096
fallos = []
def chk(c, m):
    print(("OK   " if c else "FALLA"), m)
    if not c: fallos.append(m)
def foto(w, h, sem):
    r = random.Random(sem); im = Image.new("RGB", (w, h)); px = im.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = ((x * 3 + y + sem) % 256 ^ r.getrandbits(4), (x + y * 2) % 256 ^ r.getrandbits(3), (x * y // 5) % 256)
    b = io.BytesIO(); im.save(b, "JPEG", quality=85, subsampling=2); return b.getvalue()
pad = lambda b: b + bytes(-len(b) % U)
rnd = lambda n: bytes(random.getrandbits(8) for _ in range(n))
A, Bf, Cc = foto(800, 600, 1), foto(640, 480, 2), foto(480, 360, 3)       # A y B se fragmentan, C queda sano
def trozos(b): P = pad(b); return [P[i:i + U] for i in range(0, len(P), U)]
tA, tB = trozos(A), trozos(Bf)
d = bytearray(rnd(2 * U))
posA = len(d)
for t in tA[:12]: d += t                         # A parte 1
d += rnd(6 * U)
posB = len(d)
for t in tB[:9]: d += t                          # B parte 1
d += rnd(3 * U)
for t in tA[12:]: d += t                         # A parte 2 (continuación)
d += rnd(4 * U)
for t in tB[9:]: d += t                          # B parte 2
d += rnd(2 * U)
posC = len(d)
d += pad(Cc)
d += rnd(5 * U)
open(TMP + "/frag_disco.img", "wb").write(d)
src = R.RawSource(TMP + "/frag_disco.img")
rangos = [(0, len(d))]
h_sin, _ = R.carve(src, rangos, len(d), ["Fotos"], 2048)
print("sin reconstruir:", [(h["off"], h["length"]) for h in h_sin])
chk([h for h in h_sin if h["off"] == posC and h["length"] == len(Cc)] != [], "sin reconstruir: la foto sana sale completa")
chk(not any(h["off"] in (posA, posB) for h in h_sin), "sin reconstruir: las fragmentadas no salen (no se inventan archivos rotos)")
t = time.time()
h_con, _ = R.carve(src, rangos, len(d), ["Fotos"], 2048, reconstruir=True, unidad=U)
print(f"con reconstruir ({time.time()-t:.1f}s):", [(h["off"], h["length"], len(h.get("frags", []))) for h in h_con])
vol = R.CarveVolume(src, h_con)
salida = {}
grp = vol.children_of(5)[0]
for e in vol.children_of(grp.id):
    out = TMP + f"/frag_out_{e.id}.jpg"
    if os.path.exists(out): os.remove(out)
    r = vol.extract(e.id, out, force=True)
    salida[e.id] = (r[0], open(out, "rb").read())
md = lambda b: hashlib.md5(b).hexdigest()
orig = {md(A), md(Bf), md(Cc)}
rec = {md(v[1]) for v in salida.values()}
chk(rec == orig and len(salida) == 3, f"las 3 fotos (2 fragmentadas + 1 sana) salen idénticas a las originales ({len(salida)} archivos)")
chk(all(v[0] == "OK" for v in salida.values()), "estado OK al extraer")
infos = [vol.info_fila(e.id) for e in vol.children_of(grp.id)]
chk(any("fragmentos" in i for i in infos), f"la interfaz indica los reconstruidos: {infos}")
# restringido a espacio libre (solo la zona entre archivos): sigue funcionando
print("\nFALLOS:", fallos or "ninguno")
