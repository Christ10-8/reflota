import os, tempfile
TMP = tempfile.gettempdir()
import sys, io, time, random, struct, zlib
from PIL import Image, features
print("jpeg en Pillow:", features.check("jpg"))
import types
mod = types.ModuleType("jf"); mod.struct = struct
exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reflota.py")).read(), mod.__dict__)
random.seed(2)
def foto(w, h, ruido=True):
    im = Image.new("RGB", (w, h))
    px = im.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = ((x * 3 + y) % 256 ^ (random.getrandbits(5) if ruido else 0), (x + y * 2) % 256, (x * y) % 256)
    return im
casos = []
for (w, h, sub, opt, gris) in [(200, 160, 2, False, False), (203, 157, 0, False, False), (320, 240, 1, True, False), (101, 99, 2, True, False), (256, 256, 0, False, True)]:
    im = foto(w, h)
    if gris: im = im.convert("L")
    b = io.BytesIO(); kw = dict(quality=85, optimize=opt)
    if not gris: kw["subsampling"] = sub
    im.save(b, "JPEG", **kw)
    casos.append((w, h, sub, opt, gris, b.getvalue()))
ok = True
for w, h, sub, opt, gris, dat in casos:
    inf = mod._jpeg_cabecera(dat)
    assert inf, "cabecera"
    t = time.time()
    st = (inf["ini"], 0, 0, 0, [0] * inf["ncomp"], 0)
    r, ult, pos = mod._jpeg_decodificar(inf, dat, st)
    print(f"{w}x{h} sub={sub} opt={opt} gris={gris}: bytes={len(dat)} estado={r} pos={pos} (esperado {len(dat)}) MCU={inf['total']} {time.time()-t:.2f}s")
    ok &= (r == mod._JS_OK and pos == len(dat))
# truncado a la mitad -> MAS ; corrupto -> ERR
w, h, sub, opt, gris, dat = casos[0]
inf = mod._jpeg_cabecera(dat)
st = (inf["ini"], 0, 0, 0, [0] * inf["ncomp"], 0)
r, _, p = mod._jpeg_decodificar(inf, dat[:len(dat) // 2], st); print("mitad:", r, p); ok &= r == mod._JS_MAS
mala = bytearray(dat); mala[len(dat)//2:len(dat)//2+3000] = bytes(random.getrandbits(8) for _ in range(3000))
r, _, p = mod._jpeg_decodificar(inf, bytes(mala), st); print("corrupto:", r, "en", p, "de", len(dat), "(ruido empieza en", len(dat)//2, ")"); ok &= r == mod._JS_ERR
print("TODO OK" if ok else "HAY FALLOS")
