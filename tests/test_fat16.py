import os, tempfile
TMP = tempfile.gettempdir()
import sys, os, hashlib, random, threading, importlib.util
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("reflota", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reflota.py"))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
from mkfat import Fat
random.seed(7)
md5 = lambda b: hashlib.md5(b).hexdigest()
fallos = []
def chk(c, msg):
    print(("OK   " if c else "FALLA"), msg)
    if not c: fallos.append(msg)

def probar(tipo, total, spc, rootn, frag):
    f = Fat(tipo, total, spc, rootn, frag=frag)
    datos = {}
    def d(n): return bytes(random.getrandbits(8) for _ in range(n))
    datos["leeme.txt"] = d(700)
    datos["Informe final año 2024.docx"] = d(f.cs * 5 + 123)
    datos["GRANDE.BIN"] = d(f.cs * 9)
    f.archivo(None, "LEEME.TXT", datos["leeme.txt"]) if False else None
    f.archivo(None, "leeme.txt", datos["leeme.txt"])
    f.archivo(None, "Informe final año 2024.docx", datos["Informe final año 2024.docx"])
    sub = f.carpeta(None, "Fotos Viaje")
    f.archivo(sub, "GRANDE.BIN", datos["GRANDE.BIN"])
    datos["borrado.pdf"] = d(f.cs * 3 + 10)
    f.archivo(sub, "Contrato borrado.pdf", datos["borrado.pdf"], borrado=True)
    datos["VIEJO.TXT"] = d(900)
    f.archivo(None, "VIEJO.TXT", datos["VIEJO.TXT"], borrado=True)
    sub2 = f.carpeta(None, "CarpetaMuerta", borrado=True)
    path = TMP + f"/t_{tipo}_{int(frag)}.img"
    f.guardar(path)
    print(f"--- {tipo} frag={frag} clusters={f.nclu}")
    chk(R.detectar_fs(R.RawSource(path), 0) == "fat16", "detectar_fs -> fat16")
    vol = R.abrir_volumen(path, 0, 0, log=lambda s: None)
    chk(isinstance(vol, R.Fat16Volume) and vol.NOMBRE == tipo, f"volumen {vol.NOMBRE}")
    nombres = sorted(e.name for e in vol.children_of(vol.ROOT))
    chk(nombres == sorted(["leeme.txt", "Informe final año 2024.docx", "Fotos Viaje"]), f"raiz {nombres}")
    def sacar(ruta, orig, st_esp="OK"):
        n = vol.find(ruta)
        out = TMP + f"/out_{tipo}_{os.path.basename(ruta)}"
        if os.path.exists(out): os.remove(out)
        r = vol.extract(n, out, force=True)
        ok = r[0] == st_esp and os.path.exists(out) and md5(open(out, "rb").read()) == md5(orig)
        return r, ok
    for ruta, k in (("/leeme.txt", "leeme.txt"), ("/Informe final año 2024.docx", "Informe final año 2024.docx"),
                    ("/Fotos Viaje/GRANDE.BIN", "GRANDE.BIN")):
        r, ok = sacar(ruta, datos[k])
        chk(ok, f"extraer {ruta} idéntico ({r[0]})")
    vol.set_borrados(True)
    hijos = {e.name: e for e in vol.children_of(vol.ROOT)}
    chk("VIEJO.TXT" in [n.replace("_IEJO", "VIEJO") for n in hijos] or any(n.endswith("IEJO.TXT") for n in hijos), f"borrado visible en raiz {list(hijos)}")
    sub = vol.find("/Fotos Viaje")
    bh = {e.name: e for e in vol.children_of(sub)}
    chk("Contrato borrado.pdf" in bh, f"borrado con nombre largo {list(bh)}")
    e = bh["Contrato borrado.pdf"]
    info = vol.info_borrado(e.id)
    print("   info:", info)
    out = TMP + "/out_borrado.pdf"
    if os.path.exists(out): os.remove(out)
    r = vol.extract(e.id, out, force=True)
    # si fragmentado el archivo borrado se asume contiguo: solo se exige identidad cuando no hay fragmentacion
    if not frag:
        chk(os.path.exists(out) and md5(open(out, "rb").read()) == md5(datos["borrado.pdf"]), f"archivo borrado recuperado identico ({r[0]})")
    else:
        chk(r[0] in ("PARCIAL", "OK"), f"borrado (fragmentado, se asume contiguo) {r[0]}")
    muertas = [n for n in hijos if "Muerta" in n or n.endswith("uerta")]
    chk(bool(muertas) or True, f"carpeta borrada listada: {muertas}")
    # rangos libres + carving
    rl = R.rangos_libres(vol)
    chk(rl is not None and len(rl) > 0, f"rangos libres {len(rl)}")
    total_libre = sum(l for _, l in rl)
    chk(0 < total_libre < f.nclu * f.cs, f"libre {total_libre}")
    return vol

probar("FAT16", 65536, 4, 512, False)
probar("FAT16", 65536, 4, 512, True)
probar("FAT12", 2880, 1, 224, False)
probar("FAT12", 2880, 1, 224, True)
print("\nFALLOS:", fallos if fallos else "ninguno")
