import os, tempfile
TMP = tempfile.gettempdir()
import sys, os, struct, zlib, random, hashlib, importlib.util, threading
spec = importlib.util.spec_from_file_location("reflota", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reflota.py"))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
random.seed(5)
fallos = []
def chk(c, m):
    print(("OK   " if c else "FALLA"), m)
    if not c: fallos.append(m)
rnd = lambda n: bytes(random.getrandbits(8) for _ in range(n))

# ------------ TIFF/RAW sintetico segun la especificacion
def ifd(e, entradas, nxt=0):
    """entradas: lista (tag, tipo, cnt, valor_4bytes_bytes). devuelve bytes de la IFD."""
    b = struct.pack(e + "H", len(entradas))
    for tag, typ, cnt, val in sorted(entradas):
        b += struct.pack(e + "HHI", tag, typ, cnt) + val.ljust(4, b"\0")
    return b + struct.pack(e + "I", nxt)

def mk_tiff(e="<", make=b"NIKON CORPORATION\0", cr2=False, dng=False, magic=42, subraw=True):
    """IFD0 (miniatura en tiras) -> SubIFD con RAW grande; Exif con maker note; todo con offsets reales."""
    P = lambda f, *a: struct.pack(e + f, *a)
    cab = (b"II" if e == "<" else b"MM") + P("H", magic) + P("I", 16) + (b"CR\x02\x00" if cr2 else b"\0\0\0\0") + b"\0\0\0\0"
    # layout: cab(16) | IFD0 | make | strip0(thumb) | exif IFD | makernote | SubIFD | raw strips
    n0 = 7 + (1 if dng else 0)
    ifd0_len = 2 + n0 * 12 + 4
    off_make = 16 + ifd0_len
    off_th = off_make + len(make)
    th = rnd(3000)
    off_exif = off_th + len(th)
    mn = rnd(500)
    n_ex = 2
    exif_len = 2 + n_ex * 12 + 4
    off_mn = off_exif + exif_len
    off_sub = off_mn + len(mn)
    n_sub = 4
    sub_len = 2 + n_sub * 12 + 4
    off_raw = off_sub + sub_len
    raw1, raw2 = rnd(40000), rnd(25000)
    ent0 = [(0x0100, 4, 1, P("I", 160)), (0x0101, 4, 1, P("I", 120)),
            (0x010F, 2, len(make), P("I", off_make)),
            (0x0111, 4, 1, P("I", off_th)), (0x0117, 4, 1, P("I", len(th))),
            (0x8769, 4, 1, P("I", off_exif)), (0x014A, 4, 1, P("I", off_sub))]
    if dng: ent0.append((0xC612, 1, 4, b"\x01\x04\x00\x00"))
    exif = ifd(e, [(0x927C, 7, len(mn), P("I", off_mn)), (0xA002, 4, 1, P("I", 6000))])
    sub = ifd(e, [(0x0100, 4, 1, P("I", 6000)), (0x0101, 4, 1, P("I", 4000)),
                  (0x0111, 4, 2, P("I", off_raw + 0)),   # dos tiras: offsets inline no caben -> se corrige abajo
                  (0x0117, 4, 2, P("I", 0))])
    # tiras con 2 valores: no caben inline (8 bytes) -> van fuera. Reubicar: tabla al final del RAW
    tabla_off = off_raw + len(raw1) + len(raw2)
    tabla_offs = P("II", off_raw, off_raw + len(raw1))
    tabla_cnts = P("II", len(raw1), len(raw2))
    sub = ifd(e, [(0x0100, 4, 1, P("I", 6000)), (0x0101, 4, 1, P("I", 4000)),
                  (0x0111, 4, 2, P("I", tabla_off)), (0x0117, 4, 2, P("I", tabla_off + 8))])
    f = bytearray(cab)
    f[4:8] = P("I", 16)
    f += ifd(e, ent0) + make + th + exif + mn + sub + raw1 + raw2 + tabla_offs + tabla_cnts
    return bytes(f)

def mk_psd(rle=True, ver=1):
    chans, alto, ancho = 3, 96, 120
    cab = b"8BPS" + struct.pack(">H", ver) + bytes(6) + struct.pack(">HIIHH", chans, alto, ancho, 8, 3)
    cuerpo = struct.pack(">I", 0) + struct.pack(">I", 20) + rnd(20) + struct.pack(">I", 100) + rnd(100)
    if rle:
        lineas = [rnd(random.randint(30, 90)) for _ in range(chans * alto)]
        tabla = b"".join(struct.pack(">H", len(l)) for l in lineas)
        return cab + cuerpo + struct.pack(">H", 1) + tabla + b"".join(lineas)
    return cab + cuerpo + struct.pack(">H", 0) + rnd(chans * alto * ancho)

def mk_rar4():
    def blk(tipo, fl, cuerpo, add=b""):
        sz = 7 + len(cuerpo)
        head = struct.pack("<BHH", tipo, fl, sz) + cuerpo
        crc = zlib.crc32(head) & 0xFFFF
        return struct.pack("<H", crc) + head[:] + add
    out = b"Rar!\x1a\x07\x00"
    out += blk(0x73, 0, b"\0\0\0\0\0\0")
    for k in range(2):
        datos = rnd(5000 + k * 777)
        cuerpo = struct.pack("<I", len(datos)) + rnd(20) + b"nombre%d.txt" % k
        out += blk(0x74, 0x8000, cuerpo, datos)
    out += blk(0x7B, 0x4000, b"")
    return out

def mk_rar5():
    def vi(n):
        o = b""
        while True:
            b = n & 0x7F; n >>= 7
            o += bytes([b | (0x80 if n else 0)])
            if not n: return o
    def blk(tipo, fl, extra, datos=b""):
        cab = vi(tipo) + vi(fl | (2 if datos else 0)) + (vi(len(datos)) if datos else b"") + extra
        sz = vi(len(cab))
        return struct.pack("<I", zlib.crc32(sz + cab) & 0xFFFFFFFF) + sz + cab + datos
    out = b"Rar!\x1a\x07\x01\x00" + blk(1, 0, vi(0))
    for k in range(2):
        out += blk(2, 0, rnd(20), rnd(6000 + k * 100))
    out += blk(5, 0, vi(0))
    return out

def mk_raf():
    jpg, cfa = rnd(8000), rnd(30000)
    cab = bytearray(b"FUJIFILMCCD-RAW 0201" + b"FF129502" + b"X100".ljust(32, b"\0") + b"0100" + bytes(16))
    cab = cab.ljust(108, b"\0")
    cab[84:88] = struct.pack(">I", 108); cab[88:92] = struct.pack(">I", len(jpg))
    cab[92:96] = struct.pack(">I", 108 + len(jpg)); cab[96:100] = struct.pack(">I", 100)
    cab[100:104] = struct.pack(">I", 108 + len(jpg) + 100); cab[104:108] = struct.pack(">I", len(cfa))
    return bytes(cab) + jpg + rnd(100) + cfa

casos = [("nef", mk_tiff("<", b"NIKON CORPORATION\0")), ("arw", mk_tiff("<", b"SONY\0")),
         ("cr2", mk_tiff("<", b"Canon\0", cr2=True)), ("dng", mk_tiff("<", b"Leica\0", dng=True)),
         ("tif", mk_tiff(">", b"Generic\0")), ("pef", mk_tiff("<", b"PENTAX Corporation\0")),
         ("psd", mk_psd(True)), ("psd", mk_psd(False)), ("psb", mk_psd(True, ver=2)),
         ("rar", mk_rar4()), ("rar", mk_rar5()), ("raf", mk_raf())]
# PSB usa tabla de largos de 4 bytes: regenerar bien
def mk_psb():
    chans, alto, ancho = 3, 96, 120
    cab = b"8BPS" + struct.pack(">H", 2) + bytes(6) + struct.pack(">HIIHH", chans, alto, ancho, 8, 3)
    cuerpo = struct.pack(">I", 0) + struct.pack(">I", 20) + rnd(20) + struct.pack(">Q", 100) + rnd(100)
    lineas = [rnd(random.randint(30, 90)) for _ in range(chans * alto)]
    return cab + cuerpo + struct.pack(">H", 1) + b"".join(struct.pack(">I", len(l)) for l in lineas) + b"".join(lineas)
casos[8] = ("psb", mk_psb())

# disco de ruido con cada archivo en un offset multiplo de 512 (sin que ninguno quede dentro de otro)
SECT = 512
disco = bytearray(os.urandom(2 << 20))
pos = 4096
colocados = []
for ext, dat in casos:
    # el relleno de ruido se rellena de bytes aleatorios (os.urandom) - evita firmas accidentales casi seguro
    disco[pos:pos + len(dat)] = dat
    colocados.append((pos, ext, dat))
    pos += (len(dat) // SECT + 3) * SECT
open(TMP + "/ruido_fmt.img", "wb").write(disco)
src = R.RawSource(TMP + "/ruido_fmt.img")
hits, completo = R.carve(src, [(0, len(disco))], len(disco), min_size=2048)
print([(h["off"], h["length"], h["ext"]) for h in hits])
for pos, ext, dat in colocados:
    h = [x for x in hits if x["off"] == pos]
    ok = bool(h) and h[0]["length"] == len(dat) and h[0]["ext"] == ext and bytes(disco[pos:pos + h[0]["length"]]) == dat
    chk(ok, f"{ext:4s} en {pos}: largo {len(dat)} -> {h[0]['length'] if h else None} ext {h[0]['ext'] if h else None}")
extra = [h for h in hits if h["off"] not in {c[0] for c in colocados}]
chk(not extra, f"sin falsos positivos ({len(extra)})")
# filtro de grupos: solo Comprimidos -> solo rar
h2, _ = R.carve(src, [(0, len(disco))], len(disco), grupos=["Comprimidos"], min_size=2048)
chk(sorted(x["ext"] for x in h2) == ["rar", "rar"], "grupo Comprimidos -> 2 rar")
# CR3: contenedor mp4 con marca crx
def box(t, d): return struct.pack(">I", 8 + len(d)) + t + d
cr3 = box(b"ftyp", b"crx \x00\x00\x00\x01crx isom") + box(b"moov", rnd(3000)) + box(b"mdat", rnd(20000))
d2 = bytearray(os.urandom(256 << 10)); d2[2048:2048 + len(cr3)] = cr3
open(TMP + "/ruido_cr3.img", "wb").write(d2)
h3, _ = R.carve(R.RawSource(TMP + "/ruido_cr3.img"), [(0, len(d2))], len(d2), min_size=2048)
chk(len(h3) == 1 and h3[0]["ext"] == "cr3" and h3[0]["length"] == len(cr3), f"cr3 {h3}")
print("\nFALLOS:", fallos or "ninguno")
