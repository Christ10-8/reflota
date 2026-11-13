"""Generador minimo de imagenes FAT12/FAT16 para pruebas (sin mkfs.vfat disponible en el sandbox)."""
import struct, os, random

def _chk(n11):
    s = 0
    for c in n11:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s

def _lfn_entries(nombre, n11):
    chk = _chk(n11)
    u = nombre.encode("utf-16le") + b"\x00\x00"
    u += b"\xff" * ((-len(u)) % 26)
    trozos = [u[i:i + 26] for i in range(0, len(u), 26)]
    out = []
    for k, t in enumerate(trozos):
        ordn = k + 1 | (0x40 if k == len(trozos) - 1 else 0)
        e = bytearray(32)
        e[0] = ordn
        e[1:11] = t[0:10]; e[11] = 0x0F; e[13] = chk; e[14:26] = t[10:22]; e[28:32] = t[22:26]
        out.append(bytes(e))
    return list(reversed(out))

class Fat:
    def __init__(self, tipo="FAT16", total=65536, spc=4, rootn=512, bps=512, frag=False):
        self.tipo, self.total, self.spc, self.rootn, self.bps = tipo, total, spc, rootn, bps
        rootsec = rootn * 32 // bps
        # tamano de FAT: iterar
        fatsz = 1
        while True:
            nclu = (total - 1 - fatsz * 2 - rootsec) // spc
            need = (nclu + 2) * (1.5 if tipo == "FAT12" else 2)
            if fatsz * bps >= need:
                break
            fatsz += 1
        self.fatsz, self.rootsec, self.nclu = fatsz, rootsec, nclu
        if tipo == "FAT12": assert nclu < 4085, nclu
        else: assert 4085 <= nclu < 65525, nclu
        self.img = bytearray(total * bps)
        self.fat = [0] * (nclu + 2)
        self.fat[0] = 0xFF8 if tipo == "FAT12" else 0xFFF8
        self.fat[1] = 0xFFF if tipo == "FAT12" else 0xFFFF
        self.eoc = 0xFFF if tipo == "FAT12" else 0xFFFF
        self.next = 2
        self.frag = frag
        self.root = bytearray(rootn * 32)
        self.rootpos = 0
        self.dirs = {}      # c0 -> bytearray de carpeta (se escribe al final)
        self.sfn = 0
        self.cs = spc * bps
        self.data_off = (1 + 2 * fatsz + rootsec) * bps

    def _alloc(self, n, salto=0):
        cl = []
        c = self.next
        while len(cl) < n:
            if self.fat[c] == 0:
                cl.append(c)
                if self.frag and len(cl) % 2 == 1:
                    c += 2          # deja un hueco para que quede fragmentado
                    continue
            c += 1
        # (si frag dejo huecos, quedan libres para el siguiente archivo)
        self.next = max(self.next, max(cl) + 1) if not self.frag else self.next
        for a, b in zip(cl, cl[1:] + [self.eoc]):
            self.fat[a] = b
        return cl

    def _escribir(self, cl, data):
        for i, c in enumerate(cl):
            o = self.data_off + (c - 2) * self.cs
            self.img[o:o + self.cs] = data[i * self.cs:(i + 1) * self.cs].ljust(self.cs, b"\0")

    def _short(self, nombre):
        base, _, ext = nombre.upper().partition(".")
        ok = len(base) <= 8 and len(ext) <= 3 and all(ch.isalnum() or ch in "_-" for ch in base + ext) and nombre == nombre.upper()
        if ok:
            return (base.ljust(8) + ext.ljust(3)).encode("cp850"), False
        self.sfn += 1
        b = "".join(ch for ch in base if ch.isalnum())[:6].ljust(6, "X")
        return (f"{b}~{self.sfn % 10}".ljust(8) + ext[:3].ljust(3)).encode("cp850"), True

    def _entrada(self, nombre, attr, c0, size, borrado=False, lfn_borrar=True):
        n11, necesita_lfn = self._short(nombre)
        ents = []
        if necesita_lfn:
            ents += _lfn_entries(nombre, n11)
        e = bytearray(32)
        e[0:11] = n11; e[11] = attr
        struct.pack_into("<HHHHHHHI", e, 12, 0, 0, 0, 0, 0, 0, c0 and 0, 0) if False else None
        struct.pack_into("<H", e, 0x16, (12 << 11) | (30 << 5) | 0)      # hora 12:30:00
        struct.pack_into("<H", e, 0x18, ((2024 - 1980) << 9) | (6 << 5) | 15)   # 15/06/2024
        struct.pack_into("<H", e, 0x1A, c0)
        struct.pack_into("<I", e, 0x1C, size)
        ents.append(bytes(e))
        if borrado:
            ents = [bytes([0xE5]) + x[1:] for x in ents]
        return b"".join(ents)

    def _put(self, carpeta, raw):
        if carpeta is None:
            assert self.rootpos + len(raw) <= len(self.root), "raiz llena"
            self.root[self.rootpos:self.rootpos + len(raw)] = raw
            self.rootpos += len(raw)
        else:
            self.dirs[carpeta].extend(raw)

    def archivo(self, carpeta, nombre, data, borrado=False):
        n = -(-len(data) // self.cs)
        cl = self._alloc(n) if n else []
        if cl: self._escribir(cl, data)
        self._put(carpeta, self._entrada(nombre, 0x20, cl[0] if cl else 0, len(data), borrado))
        if borrado:
            for c in cl: self.fat[c] = 0
        return cl

    def carpeta(self, padre, nombre, borrado=False):
        cl = self._alloc(1)
        c0 = cl[0]
        self.dirs[c0] = bytearray()
        d = self.dirs[c0]
        for nm, cc in ((b".          ", c0), (b"..         ", padre or 0)):
            e = bytearray(32); e[0:11] = nm; e[11] = 0x10
            struct.pack_into("<H", e, 0x1A, cc)
            d.extend(e)
        self._put(padre, self._entrada(nombre, 0x10, c0, 0, borrado))
        if borrado: self.fat[c0] = 0
        return c0

    def guardar(self, path):
        for c0, d in self.dirs.items():
            assert len(d) <= self.cs
            self.img[self.data_off + (c0 - 2) * self.cs:self.data_off + (c0 - 2) * self.cs + len(d)] = d
        b = bytearray(512)
        b[0:3] = b"\xeb\x3c\x90"; b[3:11] = b"MSDOS5.0"
        tot = self.total
        struct.pack_into("<HBHBHH", b, 0x0B, self.bps, self.spc, 1, 2, self.rootn, tot if tot < 65536 else 0)
        b[0x15] = 0xF0 if self.tipo == "FAT12" else 0xF8
        struct.pack_into("<H", b, 0x16, self.fatsz)
        struct.pack_into("<HHI", b, 0x18, 63, 255, 0)
        struct.pack_into("<I", b, 0x20, 0 if tot < 65536 else tot)
        b[0x24] = 0x80; b[0x26] = 0x29; struct.pack_into("<I", b, 0x27, 0x1234ABCD)
        b[0x2B:0x36] = b"TESTFAT    "; b[0x36:0x3E] = (self.tipo.ljust(8)).encode()
        b[510:512] = b"\x55\xaa"
        self.img[0:512] = b
        # FAT
        if self.tipo == "FAT12":
            t = bytearray(self.fatsz * self.bps)
            for c, v in enumerate(self.fat):
                o = c + (c >> 1)
                if c & 1:
                    t[o] = (t[o] & 0x0F) | ((v & 0x0F) << 4); t[o + 1] = (v >> 4) & 0xFF
                else:
                    t[o] = v & 0xFF; t[o + 1] = (t[o + 1] & 0xF0) | ((v >> 8) & 0x0F)
        else:
            t = bytearray(self.fatsz * self.bps)
            for c, v in enumerate(self.fat):
                struct.pack_into("<H", t, c * 2, v)
        for k in range(2):
            o = (1 + k * self.fatsz) * self.bps
            self.img[o:o + len(t)] = t
        ro = (1 + 2 * self.fatsz) * self.bps
        self.img[ro:ro + len(self.root)] = self.root
        with open(path, "wb") as f:
            f.write(self.img)
