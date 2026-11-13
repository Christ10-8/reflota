import os, tempfile
TMP = tempfile.gettempdir()
import sys, io, time, random, struct, bisect, types
from PIL import Image
mod = types.ModuleType("jf"); mod.struct = struct; mod.time = time; mod.bisect = bisect
exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reflota.py")).read(), mod.__dict__)
random.seed(4)
U = 4096
class Src:
    def __init__(self, d): self.d = d
    def read(self, off, n): return bytes(self.d[off:off + n]).ljust(n, b"\0") if off < len(self.d) else b""
def foto(w, h, semilla):
    r = random.Random(semilla)
    im = Image.new("RGB", (w, h)); px = im.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = ((x * 3 + y + semilla) % 256 ^ r.getrandbits(5), (x + y * 2) % 256 ^ r.getrandbits(3), (x * y // 3) % 256)
    b = io.BytesIO(); im.save(b, "JPEG", quality=85, subsampling=2); return b.getvalue()
def pad(b): return b + bytes(-len(b) % U)
fallos = []
def chk(c, m):
    print(("OK   " if c else "FALLA"), m)
    if not c: fallos.append(m)
def armar(frag_sizes_units, huecos, relleno):
    """devuelve (disco, original, offset_cab). El archivo se parte en pedazos (en clusters) con 'huecos' en medio."""
    jpg = foto(640, 480, 1)
    n = -(-len(jpg) // U)
    cortes = [sum(frag_sizes_units[:i]) for i in range(len(frag_sizes_units))] 
    return jpg, n

# --- Caso 1: dos fragmentos, hueco de ruido
jpg = foto(640, 480, 1); n = -(-len(jpg) // U)
print("JPEG de", len(jpg), "bytes =", n, "clusters")
def disco_con(jpg, partes, huecos, relleno_fn, extra_antes=3):
    """partes: clusters de cada fragmento salvo el ultimo (que toma el resto); huecos[i]: relleno tras el fragmento i"""
    d = bytearray()
    d += relleno_fn(extra_antes * U)
    a = len(d)
    P = pad(jpg)
    trozos = [P[i:i + U] for i in range(0, len(P), U)]
    k = 0
    for i, cnt in enumerate(partes):
        for t in trozos[k:k + cnt]: d += t
        k += cnt
        d += relleno_fn(huecos[i] * U)
    for t in trozos[k:]: d += t
    d += relleno_fn(5 * U)
    return bytes(d), a
rnd = lambda n: bytes(random.getrandbits(8) for _ in range(n))
for nombre, partes, huecos in [("2 fragmentos, hueco 7", [20], [7]), ("2 fragmentos, hueco 1", [11], [1]),
                               ("3 fragmentos", [15, 12], [6, 30]), ("4 fragmentos", [8, 9, 10], [2, 40, 5])]:
    disco, a = disco_con(jpg, partes, huecos, rnd)
    t = time.time()
    r = mod.reconstruir_jpeg(Src(disco), a, len(disco), U)
    dt = time.time() - t
    if r:
        rec = b"".join(disco[o:o + l] for o, l in r["frags"])
        chk(rec == jpg, f"{nombre}: reconstruido idéntico ({len(r['frags'])} frag, {dt:.1f}s) frags={r['frags'][:4]}")
    else:
        chk(False, f"{nombre}: no reconstruyó ({dt:.1f}s)")
# --- Caso 2: el hueco contiene datos de OTRO jpeg (mismas tablas) -> falsos candidatos
otro = foto(640, 480, 99)
def relleno_jpg(n):
    # trozos del medio de otro JPEG, para que parezcan datos validos
    base = pad(otro)[2 * U: 2 * U + n]
    return base.ljust(n, b"\0") if len(base) >= n else (pad(otro) * 3)[2 * U:2 * U + n]
disco, a = disco_con(jpg, [20], [10], relleno_jpg)
t = time.time(); r = mod.reconstruir_jpeg(Src(disco), a, len(disco), U); dt = time.time() - t
rec = b"".join(disco[o:o + l] for o, l in r["frags"]) if r else None
chk(rec == jpg, f"hueco con datos de otro JPEG: {'idéntico' if rec == jpg else 'FALLÓ'} ({dt:.1f}s)")
# --- Caso 3: archivo contiguo -> None (lo maneja el carving normal)
disco, a = disco_con(jpg, [], [], rnd)
chk(mod.reconstruir_jpeg(Src(disco), a, len(disco), U) is None, "contiguo: no inventa fragmentos")
# --- Caso 4: la continuación no existe (borrada/pisada): None sin colgarse
disco, a = disco_con(jpg, [20], [10], rnd)
trunc = disco[:a + 20 * U + 10 * U] + bytes(random.getrandbits(8) for _ in range(len(disco) - (a + 30 * U)))
t = time.time(); r = mod.reconstruir_jpeg(Src(trunc), a, len(trunc), U, tiempo=20); dt = time.time() - t
chk(r is None and dt < 25, f"sin continuación: None en {dt:.1f}s")
# --- Caso 5: restringido a rangos libres
disco, a = disco_con(jpg, [20], [7], rnd)
r = mod.reconstruir_jpeg(Src(disco), a, len(disco), U, rangos=[(a + 27 * U, len(disco) - (a + 27 * U))])
rec = b"".join(disco[o:o + l] for o, l in r["frags"]) if r else None
chk(rec == jpg, "con rangos libres")
print("\nFALLOS:", fallos or "ninguno")
