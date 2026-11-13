import os, tempfile
TMP = tempfile.gettempdir()
import sys, os, hashlib, random, struct, importlib.util
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("reflota", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reflota.py"))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
from mkfat import Fat
random.seed(11)
fallos=[]
def chk(c,m):
    print(("OK   " if c else "FALLA"), m)
    if not c: fallos.append(m)
def d(n): return bytes(random.getrandbits(8) for _ in range(n))

# --- disco MBR con 2 particiones: FAT16 (1 MiB) y FAT12 (despues), y una NTFS-falsa no; mas ruido en medio
f16 = Fat("FAT16", 65536, 4, 512); f16.archivo(None, "a.txt", d(3000)); f16.guardar(TMP + "/p16.img")
f12 = Fat("FAT12", 2880, 1, 224); f12.archivo(None, "b.txt", d(1000)); f12.guardar(TMP + "/p12.img")
MIB = 1 << 20
disco = bytearray(os.urandom(0) )
total = 64 * MIB
img = bytearray(total)
o16 = MIB; o12 = 40 * MIB
img[o16:o16 + len(f16.img)] = open(TMP + "/p16.img", "rb").read()
img[o12:o12 + len(f12.img)] = open(TMP + "/p12.img", "rb").read()
def ent(tipo, lba, n): return struct.pack("<B3sB3sII", 0, b"\0\0\0", tipo, b"\0\0\0", lba, n)
mbr = bytearray(512)
mbr[446:462] = ent(0x06, o16 // 512, len(f16.img) // 512)
mbr[462:478] = ent(0x01, o12 // 512, len(f12.img) // 512)
mbr[510:512] = b"\x55\xaa"
img[0:512] = mbr
open(TMP + "/disco16.img", "wb").write(img)

src = R.RawSource(TMP + "/disco16.img")
ps = R.particiones_con_fs(src, total)
print([ (p["offset"], p["fs"]) for p in ps])
chk([p["fs"] for p in ps] == ["FAT16", "FAT12"], "particiones_con_fs detecta FAT16 y FAT12")

# --- sin tabla de particiones: buscar_particiones
img[0:512] = bytes(512)
open(TMP + "/disco16_sintabla.img", "wb").write(img)
src = R.RawSource(TMP + "/disco16_sintabla.img")
res = R.buscar_particiones(src, total)
print([(p["offset"], p["fs"], p["length"]) for p in res])
chk([(p["offset"], p["fs"]) for p in res] == [(o16, "FAT16"), (o12, "FAT12")], "buscar_particiones encuentra FAT16 y FAT12 sin tabla")
chk(res and res[0]["length"] == len(f16.img) and res[1]["length"] == len(f12.img), "largos exactos")

# --- abrir por offset desde el disco completo
vol = R.abrir_volumen(TMP + "/disco16.img", o16, 0, log=lambda s: None)
chk(vol.NOMBRE == "FAT16", "abrir_volumen con offset")
n = vol.find("/a.txt")
r = vol.extract(n, TMP + "/o_a.txt", force=True)
chk(r[0] == "OK", "extraer desde disco con offset")
print("\nFALLOS:", fallos or "ninguno")
