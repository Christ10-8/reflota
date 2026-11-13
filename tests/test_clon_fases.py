import os, tempfile
TMP = tempfile.gettempdir()
import sys, os, random, hashlib, threading, importlib.util, shutil
spec = importlib.util.spec_from_file_location("reflota", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reflota.py"))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
random.seed(1)
SEC = 512
fallos = []
def chk(c, m):
    print(("OK   " if c else "FALLA"), m)
    if not c: fallos.append(m)

class Flaky:
    """Origen con sectores ilegibles: cualquier lectura que toque uno falla (como un disco real)."""
    def __init__(self, path, malos, transitorios=()):
        self.path = path; self.f = open(path, "rb"); self.malos = set(malos)
        self.trans = dict.fromkeys(transitorios, 2)       # fallan 2 veces y despues se leen bien
        self.lecturas = 0; self.toques_malos = 0; self.zero_filled = 0; self.bad = set()
        self.alto_tras = None; self.stop = None
    def read(self, off, n):
        self.f.seek(off); return self.f.read(n).ljust(n, b"\0")
    def read_strict(self, off, n):
        self.lecturas += 1
        if self.alto_tras and self.lecturas == self.alto_tras: self.stop.set()
        for s in range(off - off % SEC, off + n, SEC):
            if s in self.malos:
                self.toques_malos += 1
                raise OSError("sector ilegible")
            if self.trans.get(s, 0) > 0:
                self.trans[s] -= 1
                raise OSError("falla transitoria")
        self.f.seek(off); return self.f.read(n).ljust(n, b"\0")

TAM = 4 << 20
orig = bytearray(os.urandom(TAM))
open(TMP + "/flaky_src.img", "wb").write(orig)
# sectores malos: aislados, un grupo chico y una zona grande (1 MiB) + uno transitorio
malos = {7 * SEC, 1000 * SEC, 1001 * SEC, 1002 * SEC, (3 << 20) // SEC * SEC + SEC}
malos |= set(range(2 << 20, (2 << 20) + (1 << 20), SEC))          # 1 MiB ilegible desde los 2 MiB
trans = [500 * SEC]
def esperado(malos_):
    e = bytearray(orig)
    for m in malos_: e[m:m + SEC] = bytes(SEC)
    return bytes(e)

def correr(nombre, **kw):
    for ext in ("", ".mapa", ".origen", ".malos.txt"):
        if os.path.exists(TMP + "/flaky_dst.img" + ext): os.remove(TMP + "/flaky_dst.img" + ext)
    return None

# 1) copia completa
correr("x")
src = Flaky(TMP + "/flaky_src.img", malos, trans)
fases = []
res = R.clonar_fases(src, TMP + "/flaky_dst.img", 0, TAM, bloque=64 << 10, reintentos=2,
                     progress=lambda a, b, c, v, f: fases.append(f))
dst = open(TMP + "/flaky_dst.img", "rb").read()
chk(res["estado"] == "completo", f"estado {res['estado']} fase final {res['fase']}")
chk(sorted(res["malos"]) == sorted(malos), f"sectores malos exactos ({len(res['malos'])} de {len(malos)})")
chk(dst == esperado(malos), "imagen idéntica al original salvo ceros en los malos (el transitorio se rescató)")
chk(500 * SEC not in res["malos"] and dst[500 * SEC:501 * SEC] == bytes(orig[500 * SEC:501 * SEC]), "sector transitorio recuperado en el reintento")
chk(list(dict.fromkeys(fases)) == ["copiar", "recortar", "raspar", "reintentar"], f"orden de fases {list(dict.fromkeys(fases))}")
txt = open(TMP + "/flaky_dst.img.malos.txt").read().split("\n")
chk(sorted(int(x) for x in txt if x.isdigit()) == sorted(malos), "malos.txt coincide")
# efecto ddrescue: con la zona grande mala no se insiste en todos los sectores de la zona durante la fase 1
src2 = Flaky(TMP + "/flaky_src.img", malos)
R.clonar_fases(src2, TMP + "/flaky_dst2.img", 0, TAM, bloque=64 << 10, reintentos=0)
print("   lecturas que tocaron sectores malos:", src2.toques_malos)

# 2) parar a mitad y reanudar
correr("y")
src3 = Flaky(TMP + "/flaky_src.img", malos)
ev = threading.Event(); src3.stop = ev; src3.alto_tras = 25
r1 = R.clonar_fases(src3, TMP + "/flaky_dst.img", 0, TAM, ev, bloque=64 << 10)
chk(r1["estado"] == "detenido" and r1["pendiente"] > 0, f"detenida con {r1['pendiente']} bytes pendientes")
chk(os.path.exists(TMP + "/flaky_dst.img.mapa"), "mapa guardado")
src4 = Flaky(TMP + "/flaky_src.img", malos)
r2 = R.clonar_fases(src4, TMP + "/flaky_dst.img", 0, TAM, None, bloque=64 << 10, reintentos=0)
chk(r2["estado"] == "completo" and open(TMP + "/flaky_dst.img", "rb").read() == esperado(malos), "reanudada: imagen final idéntica")
chk(src4.lecturas < src2.lecturas, f"al reanudar no repite lo ya copiado (lecturas {src4.lecturas} < completa {src2.lecturas})")
# 3) otro origen con mismo nombre: no reanuda
open(TMP + "/flaky_src2.img", "wb").write(os.urandom(TAM))
src5 = Flaky(TMP + "/flaky_src2.img", set())
src5.path = TMP + "/flaky_src.img"           # mismo nombre, otro contenido
r3 = R.clonar_fases(src5, TMP + "/flaky_dst.img", 0, TAM, bloque=64 << 10)
chk(open(TMP + "/flaky_dst.img", "rb").read() == open(TMP + "/flaky_src2.img", "rb").read(), "origen distinto con igual nombre: copia desde cero, sin mezclar")
# 4) disco sano: sin malos ni .malos.txt
src6 = Flaky(TMP + "/flaky_src.img", set())
correr("z")
r4 = R.clonar_fases(src6, TMP + "/flaky_dst.img", 0, TAM, bloque=1 << 20)
chk(r4["estado"] == "completo" and not r4["malos"] and not os.path.exists(TMP + "/flaky_dst.img.malos.txt") and open(TMP + "/flaky_dst.img", "rb").read() == bytes(orig), "disco sano: copia idéntica, sin lista de malos")
# 5) partición con offset (no múltiplo de 4096)
src7 = Flaky(TMP + "/flaky_src.img", {(512 * 1000)})
correr("w")
r5 = R.clonar_fases(src7, TMP + "/flaky_dst.img", 512 * 100, 1 << 20, bloque=64 << 10, reintentos=0)
ex = bytearray(orig[512 * 100:512 * 100 + (1 << 20)]); ex[512 * 900:512 * 901] = bytes(512)
chk(open(TMP + "/flaky_dst.img", "rb").read() == bytes(ex) and r5["malos"] == [512 * 900], "con offset: malos relativos al inicio de la copia")
# MapaClon
m = R.MapaClon(1000); m.set(100, 200, "+"); m.set(150, 100, "-"); m.set(0, 50, "+")
chk(m.r == [(0, 50, "+"), (50, 50, "?"), (100, 50, "+"), (150, 100, "-"), (250, 50, "+"), (300, 700, "?")], f"MapaClon {m.r}")
print("\nFALLOS:", fallos or "ninguno")
