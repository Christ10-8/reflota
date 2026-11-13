import os, tempfile
TMP = tempfile.gettempdir()
import sys, os, hashlib, random, threading, shutil, importlib.util
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("reflota", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reflota.py"))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
from mkfat import Fat
random.seed(3)
fallos = []
def chk(c, m):
    print(("OK   " if c else "FALLA"), m)
    if not c: fallos.append(m)
d = lambda n: bytes(random.getrandbits(8) for _ in range(n))
md5 = lambda b: hashlib.md5(b).hexdigest()

f = Fat("FAT16", 65536, 4, 512)
D = {}
D["a"] = d(5000); D["b"] = d(9000); D["c"] = d(3000); D["x"] = d(7000); D["del"] = d(6000); D["pdf"] = d(4100)
f.archivo(None, "Facturación 2024.pdf", D["a"])
c1 = f.carpeta(None, "Clientes")
c2 = f.carpeta(c1, "Año Pasado")
f.archivo(c2, "factura marzo.pdf", D["b"])
f.archivo(c1, "notas.txt", D["c"])
c3 = f.carpeta(None, "Backups")
f.archivo(c3, "notas.txt", D["x"])                       # mismo nombre en otra carpeta
f.archivo(c3, "Factura vieja.pdf", D["del"], borrado=True)
f.archivo(c3, "foto_01.jpg", D["pdf"])
f.carpeta(None, "FacturasCarpeta")
f.guardar(TMP + "/busq.img")
vol = R.abrir_volumen(TMP + "/busq.img", 0, 0, log=lambda s: None)

def nombres(h): return sorted(x["ruta"] for x in h)
h, ok = R.buscar_nombre(vol, "factura", borrados=False)
print(nombres(h))
chk(ok and nombres(h) == ["/Clientes/Año Pasado/factura marzo.pdf", "/Facturación 2024.pdf", "/FacturasCarpeta"], "'factura' sin borrados (sin acentos, mayúsculas, carpetas)")
chk(vol.mostrar_borrados is False, "estado de borrados restaurado")
h, ok = R.buscar_nombre(vol, "factura", borrados=True)
print(nombres(h))
chk("/Backups/Factura vieja.pdf" in nombres(h) or any(x["borrado"] and x["name"].lower().endswith("actura vieja.pdf") for x in h), "con borrados aparece el borrado")
chk(vol.mostrar_borrados is False, "estado de borrados restaurado (2)")
h, _ = R.buscar_nombre(vol, "*.pdf", borrados=False)
chk(nombres(h) == ["/Clientes/Año Pasado/factura marzo.pdf", "/Facturación 2024.pdf"], f"patron *.pdf {nombres(h)}")
h, _ = R.buscar_nombre(vol, "ano pasado")
chk(nombres(h) == ["/Clientes/Año Pasado"], f"'ano pasado' (sin acento) {nombres(h)}")
h, _ = R.buscar_nombre(vol, "foto_??.jpg")
chk(nombres(h) == ["/Backups/foto_01.jpg"], "patron con ?")
h, _ = R.buscar_nombre(vol, "   ")
chk(h == [], "consulta vacía")
h, ok = R.buscar_nombre(vol, "notas")
chk(len(h) == 2, "dos 'notas.txt'")
# detener
ev = threading.Event(); ev.set()
h, ok = R.buscar_nombre(vol, "a", stop=ev)
chk(ok is False, "detenible")
# SearchVolume + copia
h, _ = R.buscar_nombre(vol, "notas")
sv = R.SearchVolume(vol, h, "notas")
ents = sv.children_of(sv.ROOT)
chk(sorted(e.dest for e in ents) == ["notas (2).txt", "notas.txt"], f"destinos únicos {[e.dest for e in ents]}")
h, _ = R.buscar_nombre(vol, "clientes")
sv2 = R.SearchVolume(vol, h)
sel = R.Selection(sv2)
e = sv2.children_of(sv2.ROOT)[0]
chk(e.is_dir and sv2.tiene_hijos(e.id), "carpeta hallada tiene hijos")
sel.explicit[e.id] = True
files, total = sel.total_size()
chk(files == 2 and total == len(D["b"]) + len(D["c"]), f"tamaño de carpeta hallada {files} {total}")
dest = TMP + "/dest_busq"; shutil.rmtree(dest, ignore_errors=True)
st = R.copy_selected(sv2, sel, dest, threading.Event(), True)
print(st)
def leer(*rel): return open(os.path.join(dest, *rel), "rb").read()
chk(md5(leer("Clientes", "Año Pasado", "factura marzo.pdf")) == md5(D["b"]) and md5(leer("Clientes", "notas.txt")) == md5(D["c"]),
    "copiada la carpeta hallada con su estructura e idéntica")
# archivo suelto hallado -> copia plana
h, _ = R.buscar_nombre(vol, "foto_01")
sv3 = R.SearchVolume(vol, h); sel3 = R.Selection(sv3)
sel3.explicit[sv3.children_of(5)[0].id] = True
dest3 = TMP + "/dest_busq3"; shutil.rmtree(dest3, ignore_errors=True)
R.copy_selected(sv3, sel3, dest3, threading.Event(), True)
chk(md5(open(os.path.join(dest3, "foto_01.jpg"), "rb").read()) == md5(D["pdf"]), "archivo hallado copiado idéntico")
# borrados en SearchVolume
h, _ = R.buscar_nombre(vol, "vieja", borrados=True)
sv4 = R.SearchVolume(vol, h)
chk(sv4.children_of(5) == [], "borrado oculto si no se pidió mostrarlos")
sv4.set_borrados(True)
e4 = sv4.children_of(5)
chk(len(e4) == 1 and "Backups" in sv4.info_borrado(e4[0].id), f"borrado visible con ruta: {sv4.info_borrado(e4[0].id) if e4 else None}")
print("\nFALLOS:", fallos or "ninguno")
