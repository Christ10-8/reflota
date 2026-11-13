#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reflota.py - REFLOTA: recuperador gratuito de archivos para NTFS, FAT32, FAT16/12 y exFAT, en solo lectura.
En NTFS lee la tabla MFT directamente (sin pytsk3, sin depender de los indices de carpetas).

POR QUE EXISTE
  pytsk3/Sleuth Kit recorre las carpetas por sus indices B-tree ($INDEX_ROOT /
  $INDEX_ALLOCATION). Si esos indices estan danados, se cuelga o no ve nada.
  Este programa hace lo que describen los recuperadores de MFT: lee TODA la $MFT
  de corrido, y arma el arbol de carpetas con la "referencia al padre" que cada
  archivo guarda en su propio registro ($FILE_NAME). No necesita los indices.

QUE HACE
  - Lee el disco en SOLO LECTURA (\\\\.\\PhysicalDriveN, o una imagen .img).
  - Si hay sectores ilegibles los rellena con ceros, los anota y sigue.
  - Si el sector de arranque esta danado: prueba la copia de respaldo, la copia
    de la $MFT ($MFTMirr) y ubicaciones tipicas de la MFT.
  - Recupera NTFS, FAT32, FAT16, FAT12 y exFAT (el formato se detecta solo, tambien con el arranque danado).
  - Menu Herramientas: BUSQUEDA POR CONTENIDO (carving, 22+ formatos, en espacio libre o en todo),
    PARTICIONES PERDIDAS (aun sin tabla ni sectores de arranque) y COPIA SEGURA a imagen (sectores
    malos en ceros + lista, reanudable).
  - ARCHIVOS BORRADOS: con "Incluir archivos borrados" aparecen en su carpeta original (en rojo),
    con el estado de cada uno (recuperable / % intacto / sobrescrito). NTFS: registros libres de la
    MFT + $Bitmap. FAT32/exFAT: entradas de carpeta borradas (se asume archivo contiguo; en FAT32 los
    nombres cortos pierden la 1ra letra si no tienen nombre largo).
  - Un solo arbol: Discos > Particiones > Carpetas. Tildar un disco/particion = copiar todo;
    tildar carpetas o archivos = copiar solo eso. El tamano se calcula solo.
  - Avisa si el destino esta en el mismo disco que el origen. Reanudable.

REQUISITOS
  Python 3.8+ (tkinter viene con Python en Windows). NO hace falta instalar nada.
  Windows exige ADMINISTRADOR para leer discos fisicos: el programa abre sin pedirlo y lo pide
  solo cuando hace falta leer un disco.

USO (ventana)
  python reflota.py

USO (linea de comandos, util para diagnosticar)
  python reflota.py --source \\\\.\\PhysicalDrive5 --particiones
  python reflota.py --source \\\\.\\PhysicalDrive5 --offset 608174080 --ls /Programacion --borrados
  python reflota.py --source \\\\.\\PhysicalDrive5 --offset 608174080 ^
         --copiar /MisDocumentos/Fotos --dest D:\\Recuperado
"""
import argparse
import array
import bisect
import csv
import fnmatch
import hashlib
import math
import os
import pickle
import queue
import re
import shutil
import struct
import sys
import threading
import time
import unicodedata
import zlib
from collections import namedtuple

# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
SECTOR = 512
ALIGN = 4096
CHUNK = 1024 * 1024
INVALIDOS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
RESERVADOS = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}

# Indices de la tupla de cada registro
R_SEQ, R_PARENT, R_PSEQ, R_NAME, R_ISDIR, R_SIZE, R_MTIME, R_FLAGS2 = range(8)
F2_ATTRLIST = 1


class Stopped(Exception):
    pass


class NtfsError(Exception):
    pass


def limpiar(n):
    n = INVALIDOS.sub("_", n).rstrip(" .")
    if not n:
        return "_"
    if n.split(".")[0].upper() in RESERVADOS:
        n = "_" + n
    return n


def lp(p):
    """Ruta larga para Windows (>260 caracteres)."""
    p = os.path.abspath(p)
    if os.name == "nt" and not p.startswith("\\\\?\\"):
        if p.startswith("\\\\"):
            return "\\\\?\\UNC\\" + p[2:]
        return "\\\\?\\" + p
    return p


def fmt_size(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


def filetime_to_unix(ft):
    if not ft:
        return 0
    t = ft / 10_000_000 - 11644473600
    return int(t) if 0 < t < 4102444800 else 0


# --------------------------------------------------------------------------
# Lectura cruda tolerante a sectores danados
# --------------------------------------------------------------------------
class RawSource:
    """Lee un disco fisico o imagen. Siempre alineado a 4096 (Windows lo exige)."""

    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb", buffering=0)
        self.lock = threading.Lock()
        self.bad = set()        # sectores (de 512) que fallaron una vez
        self.bad_count = 0      # sectores distintos que fallaron
        self.zero_filled = 0    # sectores devueltos como ceros por error (con repeticiones)

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass

    def read(self, off, n):
        if n <= 0:
            return b""
        a0 = off - off % ALIGN
        a1 = -(-(off + n) // ALIGN) * ALIGN
        data = self._read_aligned(a0, a1 - a0)
        return data[off - a0: off - a0 + n]

    def read_strict(self, off, n):
        """Como read(), pero si el disco falla LEVANTA OSError (no rellena con ceros ni recuerda sectores malos).
        Lo usa el clonado por fases para decidir el mismo que hacer con cada zona."""
        if n <= 0:
            return b""
        a0 = off - off % ALIGN
        a1 = -(-(off + n) // ALIGN) * ALIGN
        with self.lock:
            self.f.seek(a0)
            d = self.f.read(a1 - a0)
        if len(d) < a1 - a0:
            d += bytes(a1 - a0 - len(d))
        return d[off - a0: off - a0 + n]

    def _read_aligned(self, off, n):
        with self.lock:
            try:
                self.f.seek(off)
                d = self.f.read(n)
                if len(d) == n:
                    return d
                if len(d) < n:          # fin de la imagen: completar con ceros
                    return d + bytes(n - len(d))
            except OSError:
                pass
            # Algo fallo: reintento sector por sector para aislar lo ilegible
            out = bytearray()
            for s in range(off, off + n, SECTOR):
                sec = s // SECTOR
                if sec in self.bad:
                    out += bytes(SECTOR)
                    self.zero_filled += 1
                    continue
                try:
                    self.f.seek(s)
                    d = self.f.read(SECTOR)
                    if len(d) < SECTOR:
                        d += bytes(SECTOR - len(d))
                except OSError:
                    self.bad.add(sec)
                    self.bad_count += 1
                    self.zero_filled += 1
                    d = bytes(SECTOR)
                out += d
            return bytes(out)


# --------------------------------------------------------------------------
# Particiones (MBR / GPT)
# --------------------------------------------------------------------------
Particion = namedtuple("Particion", "num offset length tipo")


def leer_particiones(src):
    parts = []
    mbr = src.read(0, 512)
    if mbr[510:512] == b"\x55\xaa":
        for i in range(4):
            e = mbr[446 + 16 * i: 462 + 16 * i]
            ptype = e[4]
            lba, cnt = struct.unpack_from("<II", e, 8)
            if ptype in (0, 0x05, 0x0F, 0x85) or cnt == 0:
                continue
            if ptype == 0xEE:
                continue
            parts.append(Particion(i + 1, lba * 512, cnt * 512, f"0x{ptype:02X}"))
    hdr = src.read(512, 512)
    if hdr[:8] == b"EFI PART":
        ent_lba, n_ent, ent_sz = struct.unpack_from("<QII", hdr, 72)
        raw = src.read(ent_lba * 512, n_ent * ent_sz)
        for i in range(n_ent):
            e = raw[i * ent_sz:(i + 1) * ent_sz]
            if len(e) < 56 or e[:16] == bytes(16):
                continue
            first, last = struct.unpack_from("<QQ", e, 32)
            parts.append(Particion(100 + i, first * 512, (last - first + 1) * 512, "GPT"))
    return parts


# --------------------------------------------------------------------------
# Estructuras NTFS
# --------------------------------------------------------------------------
def apply_fixups(rec):
    """Aplica el 'update sequence array'. Devuelve False si el registro esta roto."""
    if rec[0:4] != b"FILE":
        return False
    usa_off, usa_cnt = struct.unpack_from("<HH", rec, 4)
    if usa_cnt < 2 or usa_off + usa_cnt * 2 > len(rec):
        return False
    usn = bytes(rec[usa_off:usa_off + 2])
    for i in range(1, usa_cnt):
        end = i * 512
        if end > len(rec):
            break
        if bytes(rec[end - 2:end]) != usn:
            return False
        rec[end - 2:end] = rec[usa_off + 2 * i: usa_off + 2 * i + 2]
    return True


def iter_attrs(rec):
    off = struct.unpack_from("<H", rec, 0x14)[0]
    n = len(rec)
    while off + 16 <= n:
        t, ln = struct.unpack_from("<II", rec, off)
        if t == 0xFFFFFFFF or ln < 16 or off + ln > n:
            return
        yield off, t, ln
        off += ln


def decode_runs(data):
    runs = []
    pos = 0
    lcn = 0
    n = len(data)
    while pos < n:
        h = data[pos]
        if h == 0:
            break
        pos += 1
        ls, os_ = h & 0xF, h >> 4
        if ls == 0 or pos + ls + os_ > n:
            break
        length = int.from_bytes(data[pos:pos + ls], "little")
        pos += ls
        if os_:
            lcn += int.from_bytes(data[pos:pos + os_], "little", signed=True)
            pos += os_
            if lcn < 0:
                break
            runs.append((lcn, length))
        else:
            runs.append((None, length))
    return runs


def parse_filename(content):
    """Devuelve (parent_recno, parent_seq, namespace, name) o None."""
    if len(content) < 66:
        return None
    parent = int.from_bytes(content[0:6], "little")
    pseq = int.from_bytes(content[6:8], "little")
    nlen = content[64]
    ns = content[65]
    if 66 + 2 * nlen > len(content):
        return None
    return parent, pseq, ns, content[66:66 + 2 * nlen].decode("utf-16le", "replace")


def parse_base(rec):
    """Tupla de indice para un registro base en uso (ya con fixups), o None."""
    seq = struct.unpack_from("<H", rec, 0x10)[0]
    flags = struct.unpack_from("<H", rec, 0x16)[0]
    is_dir = bool(flags & 2)
    best = None
    mtime = 0
    size = None
    f2 = 0
    for off, t, ln in iter_attrs(rec):
        if t == 0x30:
            if rec[off + 8] != 0:
                continue
            clen, coff = struct.unpack_from("<IH", rec, off + 16)
            fn = parse_filename(rec[off + coff: off + coff + clen])
            if not fn:
                continue
            parent, pseq, ns, name = fn
            prio = 0 if ns in (1, 3) else (1 if ns == 0 else 2)
            if best is None or prio < best[0]:
                best = (prio, parent, pseq, name)
        elif t == 0x10:
            if rec[off + 8] == 0:
                clen, coff = struct.unpack_from("<IH", rec, off + 16)
                if clen >= 16:
                    mtime = filetime_to_unix(struct.unpack_from("<Q", rec, off + coff + 8)[0])
        elif t == 0x80:
            if rec[off + 9] == 0:   # sin nombre = flujo principal
                if rec[off + 8] == 0:
                    size = struct.unpack_from("<I", rec, off + 16)[0]
                else:
                    svcn = struct.unpack_from("<Q", rec, off + 16)[0]
                    if svcn == 0:
                        size = struct.unpack_from("<Q", rec, off + 48)[0]
        elif t == 0x20:
            f2 |= F2_ATTRLIST
    if best is None:
        return None
    _, parent, pseq, name = best
    if is_dir:
        size = 0
    return (seq, parent, pseq, name, is_dir, size, mtime, f2)


class RunMap:
    """Mapa de 'runs' (lcn, longitud) a bytes dentro del volumen."""

    def __init__(self, runs, cs):
        self.runs = runs
        self.cs = cs
        self.starts = []
        v = 0
        for _, ln in runs:
            self.starts.append(v)
            v += ln
        self.total_clusters = v

    def read(self, vol, off, n):
        cs = self.cs
        out = bytearray()
        end = off + n
        while off < end:
            vcn = off // cs
            if vcn >= self.total_clusters:
                out += bytes(end - off)
                break
            i = bisect.bisect_right(self.starts, vcn) - 1
            lcn, ln = self.runs[i]
            in_run = off - self.starts[i] * cs
            take = min(end - off, ln * cs - in_run)
            if lcn is None:
                out += bytes(take)
            else:
                out += vol.read_abs(lcn * cs + in_run, take)
            off += take
        return bytes(out)


Entrada = namedtuple("Entrada", "id name dest is_dir size mtime borrado", defaults=(False,))


# --------------------------------------------------------------------------
# Volumen NTFS
# --------------------------------------------------------------------------
class Volume:
    ROOT = 5
    ORPHAN = -1
    DORPHAN = -2      # borrados cuya carpeta de origen ya no se conoce

    def __init__(self, src, vol_off=0, vol_len=0, mft_cluster=None, log=None):
        self.src = src
        self.vol_off = vol_off
        self.vol_len = vol_len
        self.log = log or (lambda s: None)
        self.rec = {}
        self.recd = {}            # registros libres con nombre (archivos borrados)
        self.dchildren = {}
        self.mostrar_borrados = False
        self.skip_root = ()
        self._bm = None
        self._bm_tried = False
        self.tparent = {}
        self.children = {}
        self.orphans = []
        self._ccache = {}
        self._size_cache = {}
        self.stats = {}
        self.geom_origen = ""
        self._open(mft_cluster)

    # ---------------- apertura / geometria
    def read_abs(self, off, n):
        return self.src.read(self.vol_off + off, n)

    def _parse_boot(self, b):
        if len(b) < 512 or b[3:11] != b"NTFS    ":
            return None
        bps, spc = struct.unpack_from("<HB", b, 0x0B)
        if bps not in (512, 1024, 2048, 4096) or spc not in (1, 2, 4, 8, 16, 32, 64, 128):
            return None
        total, mft, mirr = struct.unpack_from("<QQQ", b, 0x28)
        cpr = struct.unpack_from("<b", b, 0x40)[0]
        cs = bps * spc
        rs = cpr * cs if cpr > 0 else 1 << (-cpr)
        if rs < 512 or rs > 65536 or mft == 0:
            return None
        if self.vol_len and mft * cs >= self.vol_len:
            return None
        return dict(bps=bps, cs=cs, rs=rs, mft=mft, mirr=mirr, total=total)

    def _candidatos(self, mft_cluster):
        boot = self._parse_boot(self.src.read(self.vol_off, 512))
        if boot:
            yield "sector de arranque", boot
        if self.vol_len:
            bak = self._parse_boot(self.src.read(self.vol_off + self.vol_len - 512, 512))
            if bak:
                yield "copia de respaldo del sector de arranque", bak
        if boot:
            bak2 = self._parse_boot(self.src.read(self.vol_off + boot["total"] * boot["bps"], 512))
            if bak2:
                yield "copia de respaldo (segun tamano)", bak2
        base = boot or dict(bps=512, cs=4096, rs=1024, mirr=0, total=0)
        if mft_cluster:
            g = dict(base)
            g["mft"] = mft_cluster
            g["mirr"] = 0
            yield f"cluster {mft_cluster} indicado a mano", g
        for c in (786432, 4, 16, 2, 8, 32, 64, 128, 256):
            g = dict(bps=512, cs=4096, rs=1024, mft=c, mirr=0, total=0)
            yield f"ubicacion tipica (cluster {c})", g

    def _mft_info(self, rec):
        names = []
        data = None
        for off, t, ln in iter_attrs(rec):
            if t == 0x30 and rec[off + 8] == 0:
                clen, coff = struct.unpack_from("<IH", rec, off + 16)
                fn = parse_filename(rec[off + coff: off + coff + clen])
                if fn:
                    names.append(fn[3])
            elif t == 0x80 and rec[off + 9] == 0 and rec[off + 8] == 1:
                roff = struct.unpack_from("<H", rec, off + 32)[0]
                real = struct.unpack_from("<Q", rec, off + 48)[0]
                data = (decode_runs(bytes(rec[off + roff: off + ln])), real)
        if "$MFT" not in names or not data or not data[0] or data[0][0][0] is None:
            return None
        return data

    def _open(self, mft_cluster):
        tried = []
        for desc, g in self._candidatos(mft_cluster):
            for etiqueta, loc in (("MFT", g["mft"]), ("copia $MFTMirr", g.get("mirr"))):
                if not loc:
                    continue
                raw = self.src.read(self.vol_off + loc * g["cs"], g["rs"])
                rec = bytearray(raw)
                if not apply_fixups(rec):
                    tried.append(f"{desc}/{etiqueta}: registro invalido")
                    continue
                info = self._mft_info(rec)
                if not info:
                    tried.append(f"{desc}/{etiqueta}: no es el registro de $MFT")
                    continue
                runs, real = info
                self.cs, self.rs, self.bps = g["cs"], g["rs"], g["bps"]
                self.mft_map = RunMap(runs, self.cs)
                self.mft_size = real
                # MFT muy fragmentada: puede haber mas runs en registros de extension
                if self.mft_map.total_clusters * self.cs < real:
                    di = self.get_data_info(0)
                    if di and di.get("runs"):
                        self.mft_map = RunMap(di["runs"], self.cs)
                covered = self.mft_map.total_clusters * self.cs
                if covered < real:
                    self.log(f"AVISO: la MFT declara {fmt_size(real)} pero solo se ubican {fmt_size(covered)}; "
                             f"se leera lo ubicable.")
                    self.mft_size = covered
                self.geom_origen = f"{desc} ({etiqueta})"
                self.log(f"Geometria: {self.geom_origen} | cluster {self.cs} B, registro {self.rs} B, "
                         f"MFT {fmt_size(self.mft_size)}")
                return
        raise NtfsError("No pude ubicar la $MFT. Intentos:\n  " + "\n  ".join(tried[:12]) +
                        "\nProba indicar el cluster de la MFT a mano (DMDE lo muestra como 'Clus:').")

    # ---------------- lectura de registros
    def read_record(self, recno):
        off = recno * self.rs
        if off + self.rs > self.mft_size:
            return None
        rec = bytearray(self.mft_map.read(self, off, self.rs))
        return rec if apply_fixups(rec) else None

    def scan(self, progress=None, stop=None):
        rs = self.rs
        total = self.mft_size // rs
        CH = max(rs, (4 * 1024 * 1024) // rs * rs)
        rec = {}
        recd = {}
        st = dict(registros=total, en_uso=0, malos=0, ilegibles=0, sin_nombre=0, borrados=0)
        pos = 0
        t_last = 0
        while pos < self.mft_size:
            if stop is not None and stop.is_set():
                raise Stopped()
            n = min(CH, self.mft_size - pos)
            data = self.mft_map.read(self, pos, n)
            first = pos // rs
            for i in range(n // rs):
                b = data[i * rs:(i + 1) * rs]
                if b[:4] != b"FILE":
                    if b.count(0) != rs:
                        st["ilegibles"] += 1
                    continue
                if struct.unpack_from("<Q", b, 0x20)[0] & 0xFFFFFFFFFFFF:
                    continue    # registro de extension
                if not (b[0x16] & 1):
                    # registro libre: puede ser un archivo o carpeta borrado que conserva su nombre
                    if first + i >= 24:
                        r = bytearray(b)
                        if apply_fixups(r):
                            try:
                                ed = parse_base(r)
                            except Exception:
                                ed = None
                            if ed is not None and (ed[R_ISDIR] or ed[R_SIZE] is None or ed[R_SIZE] > 0):
                                recd[first + i] = ed
                    continue
                r = bytearray(b)
                if not apply_fixups(r):
                    st["malos"] += 1
                    continue
                try:
                    e = parse_base(r)
                except Exception:
                    st["malos"] += 1
                    continue
                if e is None:
                    st["sin_nombre"] += 1
                    continue
                rec[first + i] = e
                st["en_uso"] += 1
            pos += n
            now = time.time()
            if progress and now - t_last > 0.2:
                t_last = now
                progress(pos // rs, total, st["en_uso"])
        if progress:
            progress(total, total, st["en_uso"])
        self.rec = rec
        self.recd = recd
        st["borrados"] = len(recd)
        st["sectores_ilegibles"] = self.src.bad_count
        self.stats = st
        self.build_tree()
        return st

    # ---------------- arbol
    def build_tree(self):
        children = {}
        tparent = {}
        orphans = []
        rec = self.rec
        for recno, e in rec.items():
            if recno == 5 or recno < 24:
                continue
            p = e[R_PARENT]
            pe = rec.get(p)
            if pe is not None and pe[R_ISDIR] and pe[R_SEQ] == e[R_PSEQ] and p != recno:
                children.setdefault(p, []).append(recno)
                tparent[recno] = p
            else:
                orphans.append(recno)
                tparent[recno] = self.ORPHAN
        if orphans:
            children[self.ORPHAN] = orphans
            tparent[self.ORPHAN] = self.ROOT
        # archivos borrados: se cuelgan de su carpeta original si todavia existe (en uso o tambien borrada)
        recd = self.recd
        dchildren = {}
        DO = self.DORPHAN
        for recno, e in recd.items():
            p, ps = e[R_PARENT], e[R_PSEQ]
            par = DO
            if p != recno:
                pe = rec.get(p)
                if pe is not None and pe[R_ISDIR] and pe[R_SEQ] == ps:
                    par = p
                else:
                    pd = recd.get(p)
                    if pd is not None and pd[R_ISDIR] and ps <= pd[R_SEQ] <= ps + 1:
                        par = p
            dchildren.setdefault(par, []).append(recno)
            tparent[recno] = par
        for recno in list(recd):                 # cortar ciclos entre carpetas borradas
            visto = set()
            n = recno
            while n is not None and n != self.ROOT and n in tparent:
                if n in visto:
                    dchildren[tparent[recno]].remove(recno)
                    tparent[recno] = DO
                    dchildren.setdefault(DO, []).append(recno)
                    break
                visto.add(n)
                n = tparent.get(n)
        if dchildren.get(DO):
            tparent[DO] = self.ROOT
        self.dchildren = dchildren
        tparent[self.ROOT] = None
        self.children, self.tparent, self.orphans = children, tparent, orphans
        self._ccache = {}
        self.stats["huerfanos"] = len(orphans)

    def children_of(self, node):
        c = self._ccache.get(node)
        if c is not None:
            return c
        ids = list(self.children.get(node, []))
        if node == self.ROOT and self.orphans:
            ids.append(self.ORPHAN)
        items = []
        for i in ids:
            if i == self.ORPHAN:
                items.append((i, "_huerfanos (carpeta padre desconocida)", True, 0, 0, False))
            else:
                e = self.rec[i]
                items.append((i, e[R_NAME], e[R_ISDIR], e[R_SIZE], e[R_MTIME], False))
        if self.mostrar_borrados:
            dids = list(self.dchildren.get(node, []))
            if node == self.ROOT and self.dchildren.get(self.DORPHAN):
                dids.append(self.DORPHAN)
            for i in dids:
                if i == self.DORPHAN:
                    items.append((i, "_borrados (carpeta de origen desconocida)", True, 0, 0, True))
                else:
                    e = self.recd[i]
                    items.append((i, e[R_NAME], e[R_ISDIR], e[R_SIZE], e[R_MTIME], True))
        out = armar_entradas(items)
        self._ccache[node] = out
        return out

    def find(self, path):
        comps = [c for c in path.replace("\\", "/").split("/") if c]
        node = self.ROOT
        for c in comps:
            nxt = None
            for e in self.children_of(node):
                if e.name.lower() == c.lower():
                    nxt = e.id
                    break
            if nxt is None:
                return None
            node = nxt
        return node

    def path_of(self, recno):
        names = []
        while recno is not None and recno != self.ROOT:
            if recno == self.ORPHAN:
                names.append("_huerfanos")
            elif recno == self.DORPHAN:
                names.append("_borrados")
            else:
                names.append((self.rec.get(recno) or self.recd[recno])[R_NAME])
            recno = self.tparent.get(recno)
        return "/" + "/".join(reversed(names))

    # ---------------- datos de un archivo
    def _attrlist_exts(self, rec, off, recno):
        nonres = rec[off + 8]
        if not nonres:
            clen, coff = struct.unpack_from("<IH", rec, off + 16)
            data = bytes(rec[off + coff: off + coff + clen])
        else:
            roff = struct.unpack_from("<H", rec, off + 32)[0]
            real = struct.unpack_from("<Q", rec, off + 48)[0]
            runs = decode_runs(bytes(rec[off + roff: off + struct.unpack_from("<I", rec, off + 4)[0]]))
            data = RunMap(runs, self.cs).read(self, 0, real)
        exts = set()
        pos = 0
        while pos + 26 <= len(data):
            ln = struct.unpack_from("<H", data, pos + 4)[0]
            if ln < 26:
                break
            ref = int.from_bytes(data[pos + 16:pos + 22], "little")
            if ref != recno:
                exts.add(ref)
            pos += ln
        return exts

    def get_data_info(self, recno):
        """Flujo $DATA sin nombre: dict(resident, runs, size, init, flags, incompleto) o None."""
        rec = self.read_record(recno)
        if rec is None:
            return None
        recs = [rec]
        for off, t, ln in iter_attrs(rec):
            if t == 0x20:
                for ext in sorted(self._attrlist_exts(rec, off, recno)):
                    r2 = self.read_record(ext)
                    if r2 is not None and (struct.unpack_from("<Q", r2, 0x20)[0] & 0xFFFFFFFFFFFF) == recno:
                        recs.append(r2)
        frags = []
        for r in recs:
            for off, t, ln in iter_attrs(r):
                if t != 0x80 or r[off + 9] != 0:
                    continue
                flags = struct.unpack_from("<H", r, off + 12)[0]
                if r[off + 8] == 0:
                    clen, coff = struct.unpack_from("<IH", r, off + 16)
                    frags.append((0, False, bytes(r[off + coff: off + coff + clen]), clen, clen, flags))
                else:
                    svcn = struct.unpack_from("<Q", r, off + 16)[0]
                    roff = struct.unpack_from("<H", r, off + 32)[0]
                    real, init = struct.unpack_from("<QQ", r, off + 48)
                    runs = decode_runs(bytes(r[off + roff: off + ln]))
                    frags.append((svcn, True, runs, real, init, flags))
        if not frags:
            return None
        frags.sort(key=lambda f: f[0])
        first = frags[0]
        if not first[1]:
            return dict(resident=first[2], runs=None, size=first[3], init=first[3],
                        flags=first[5], incompleto=False)
        runs = []
        for f in frags:
            if f[1]:
                runs += f[2]
        return dict(resident=None, runs=runs, size=first[3], init=first[4],
                    flags=first[5], incompleto=(first[0] != 0))

    def file_size(self, recno):
        e = self.rec.get(recno) or self.recd[recno]
        if e[R_SIZE] is not None:
            return e[R_SIZE]
        if recno in self._size_cache:
            return self._size_cache[recno]
        di = self.get_data_info(recno)
        s = di["size"] if di else 0
        self._size_cache[recno] = s
        return s

    def extract(self, recno, dst, stop=None, force=False, mtime=0):
        """Copia un archivo. Devuelve (estado, bytes, sectores_ilegibles)."""
        di = self.get_data_info(recno)
        if di is None:
            return "SIN_DATOS", 0, 0
        if di["flags"] & 0x4000:
            return "CIFRADO", 0, 0
        if di["flags"] & 0x0001 and di["runs"] is not None:
            return "COMPRIMIDO", 0, 0
        size = di["size"]
        dst = lp(dst)
        if not force and os.path.exists(dst) and os.path.getsize(dst) == size:
            return "SALTADO", size, 0
        nota = ""
        if recno in self.recd:                      # archivo borrado: puede haber sido pisado
            pct = self.estado_borrado(recno)
            if pct == 0 and size > 0 and di["resident"] is None:
                return "SOBRESCRITO", 0, 0
            if pct is not None and pct < 100:
                nota = f"borrado: {pct}% de los clusters sin reutilizar (el resto puede traer datos de otros archivos)"
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        tmp = dst + ".partial"
        z0 = self.src.zero_filled
        try:
            with open(tmp, "wb") as out:
                if di["resident"] is not None:
                    out.write(di["resident"])
                else:
                    rm = RunMap(di["runs"], self.cs)
                    off = 0
                    init = min(di["init"], size)
                    while off < size:
                        if stop is not None and stop.is_set():
                            out.close()
                            os.remove(tmp)
                            return "DETENIDO", off, 0
                        n = min(CHUNK, size - off)
                        if off >= init:
                            data = bytes(n)
                        else:
                            m = min(n, init - off)
                            data = rm.read(self, off, m) + bytes(n - m)
                        out.write(data)
                        off += n
            os.replace(tmp, dst)
        except OSError as e:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return "ERROR_ESCRITURA:" + str(e), 0, 0
        if mtime:
            try:
                os.utime(dst, (mtime, mtime))
            except OSError:
                pass
        nbad = self.src.zero_filled - z0
        st = "PARCIAL" if (nbad or nota) else ("INCOMPLETO" if di["incompleto"] else "OK")
        return st, size, nbad, nota

    # ---------------- archivos borrados
    def set_borrados(self, v):
        self.mostrar_borrados = bool(v)
        self._ccache = {}

    def es_borrado(self, i):
        return i in self.recd or i == self.DORPHAN

    def tiene_hijos(self, i):
        if self.children.get(i):
            return True
        return self.mostrar_borrados and bool(self.dchildren.get(i))

    def _cargar_bitmap(self):
        if not self._bm_tried:
            self._bm_tried = True
            try:
                di = self.get_data_info(6)           # $Bitmap: un bit por cluster (1 = ocupado)
                if di is not None:
                    if di["resident"] is not None:
                        self._bm = bytes(di["resident"])
                    else:
                        self._bm = RunMap(di["runs"], self.cs).read(self, 0, min(di["size"], 1 << 30))
            except Exception:
                self._bm = None
        return self._bm

    def estado_borrado(self, recno):
        """Porcentaje (0-100) de los clusters del archivo borrado que siguen sin reutilizar, o None."""
        di = self.get_data_info(recno)
        if di is None:
            return None
        if di["resident"] is not None:
            return 100
        bm = self._cargar_bitmap()
        if bm is None:
            return None
        libres = total = 0
        for lcn, ln in di["runs"]:
            total += ln
            libres += ln if lcn is None else ln - bits_set(bm, lcn, ln)
        return 100 if total == 0 else int(round(100 * libres / total))

    def info_borrado(self, i):
        if i not in self.recd:
            return "carpeta borrada" if i == self.DORPHAN else ""
        if self.recd[i][R_ISDIR]:
            return "carpeta borrada"
        try:
            return texto_borrado(self.estado_borrado(i))
        except Exception:
            return "borrado"

    # ---------------- indice guardado
    def index_key(self):
        return (self.vol_off, self.cs, self.rs, self.mft_size,
                self.mft_map.runs[0] if self.mft_map.runs else None)

    def save_index(self, path):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                pickle.dump(dict(key=self.index_key(), rec=self.rec, recd=self.recd, stats=self.stats), f, protocol=4)
            return True
        except Exception:
            return False

    def load_index(self, path):
        try:
            with open(path, "rb") as f:
                d = pickle.load(f)
        except Exception:
            return False
        if d.get("key") != self.index_key():
            return False
        if "recd" not in d:
            return False             # indice viejo (sin archivos borrados): releer
        self.rec = d["rec"]
        self.recd = d["recd"]
        self.stats = d["stats"]
        self.build_tree()
        return True


# --------------------------------------------------------------------------
# Utilidades comunes: archivos borrados, nombres, fechas
# --------------------------------------------------------------------------
POP = bytes(bin(i).count("1") for i in range(256))


def bits_set(bm, a, n):
    """Cantidad de bits en 1 del rango [a, a+n) de un mapa de bits (bit 0 = menos significativo)."""
    if n <= 0:
        return 0
    end = a + n
    if ((end + 7) >> 3) > len(bm):
        return n                      # fuera del mapa: lo contamos como ocupado
    b0, b1 = a >> 3, (end - 1) >> 3
    if b0 == b1:
        return POP[(bm[b0] >> (a & 7)) & ((1 << n) - 1)]
    cnt = POP[bm[b0] >> (a & 7)]
    cnt += sum(map(POP.__getitem__, bm[b0 + 1:b1]))
    cnt += POP[bm[b1] & ((1 << (((end - 1) & 7) + 1)) - 1)]
    return cnt


def texto_borrado(pct):
    if pct is None:
        return "borrado"
    if pct >= 100:
        return "borrado \u00B7 recuperable"
    if pct <= 0:
        return "borrado \u00B7 sobrescrito"
    return f"borrado \u00B7 {pct}% intacto"


def armar_entradas(items):
    """items: (id, nombre, es_dir, tamano, mtime, borrado) -> lista de Entrada ordenada,
    con un nombre de destino sin repetidos (los borrados se distinguen con '(borrado N)')."""
    items = sorted(items, key=lambda x: (not x[2], x[5], x[1].lower()))
    seen = {}
    out = []
    for (i, name, is_dir, size, mt, borrado) in items:
        d = limpiar(name)
        k = d.lower()
        if k in seen:
            stem, ext = os.path.splitext(d)
            d = f"{stem} (borrado {i}){ext}" if borrado else f"{stem}~{i}{ext}"
        seen[d.lower()] = 1
        out.append(Entrada(i, name, d, is_dir, size, mt, borrado))
    return out


def dos_time(d, t):
    """Fecha/hora estilo FAT -> segundos unix (0 si no es valida)."""
    try:
        y, mo, da = 1980 + (d >> 9), (d >> 5) & 15, d & 31
        h, mi, s = t >> 11, (t >> 5) & 63, (t & 31) * 2
        if not (1 <= mo <= 12 and 1 <= da <= 31 and h < 24 and mi < 60 and s < 60):
            return 0
        v = int(time.mktime((y, mo, da, h, mi, s, 0, 0, -1)))
        return v if v > 0 else 0
    except (OverflowError, ValueError, OSError):
        return 0


def _lfn_chk(n11):
    c = 0
    for b in n11:
        c = (((c & 1) << 7) + (c >> 1) + b) & 0xFF
    return c


# --------------------------------------------------------------------------
# Base comun de FAT32 y exFAT (directorios leidos bajo demanda, con borrados)
# --------------------------------------------------------------------------
class _FsLazy:
    ROOT = 5
    ORPHAN = -1
    NOMBRE = "FAT"
    _EOC = 0x0FFFFFF8
    _BAD = 0x0FFFFFF7
    _MASK = 0x0FFFFFFF

    def __init__(self, src, vol_off=0, vol_len=0, log=None):
        self.src = src
        self.vol_off = vol_off
        self.vol_len = vol_len
        self.log = log or (lambda s: None)
        self.tparent = {5: None}
        self.stats = {}
        self.mostrar_borrados = False
        self.skip_root = ()
        self.geom_origen = ""
        self.nfats = 1
        self._ent = {}
        self._kids = {}
        self._ccache = {}
        self._next = 100
        self._fat_cache = {}

    # ---------------- lectura
    def read_abs(self, off, n):
        return self.src.read(self.vol_off + off, n)

    def cluster_off(self, c):
        return self.data_off + (c - 2) * self.cs

    def _fat(self, c, copia=0):
        off = self.fat_off + copia * self.fat_stride + c * 4
        key = (copia, off >> 16)
        data = self._fat_cache.get(key)
        if data is None:
            if len(self._fat_cache) > 256:
                self._fat_cache.clear()
            data = self.read_abs((off >> 16) << 16, 65536)
            self._fat_cache[key] = data
        return struct.unpack_from("<I", data, off & 0xFFFF)[0] & self._MASK

    def _cadena(self, c0, need=None, maxc=None):
        """Sigue la FAT desde c0. Devuelve (runs, clusters_obtenidos, termino_bien)."""
        runs = []
        c = c0
        got = 0
        limite = self.nclu + 2
        while 2 <= c < limite and got <= limite:
            if runs and runs[-1][0] + runs[-1][1] == c:
                runs[-1] = (runs[-1][0], runs[-1][1] + 1)
            else:
                runs.append((c, 1))
            got += 1
            if (need is not None and got >= need) or (maxc is not None and got >= maxc):
                return runs, got, True
            nxt = self._fat(c)
            if nxt >= self._EOC:
                return runs, got, True
            if nxt < 2 or nxt >= limite:
                alt = self._fat(c, 1) if self.nfats > 1 else 0
                if 2 <= alt < limite:
                    nxt = alt
                else:
                    return runs, got, False
            c = nxt
        return runs, got, False

    def _leer_runs(self, runs, cap=64 << 20):
        out = bytearray()
        for c0, n in runs:
            m = min(n * self.cs, cap - len(out))
            if m <= 0:
                break
            out += self.read_abs(self.cluster_off(c0), m)
        return bytes(out)

    def _completar_contiguo(self, runs, got, need):
        """Si la cadena se corto, asume que el resto es contiguo. Devuelve runs completos."""
        last = (runs[-1][0] + runs[-1][1]) if runs else None
        if last is None or got >= need:
            return runs
        faltan = need - got
        if last + faltan > self.nclu + 2:
            faltan = max(0, self.nclu + 2 - last)
        if faltan > 0:
            runs = list(runs)
            if runs and runs[-1][0] + runs[-1][1] == last:
                runs[-1] = (runs[-1][0], runs[-1][1] + faltan)
            else:
                runs.append((last, faltan))
        return runs

    def _volcar(self, runs, size, out, stop, valid=None):
        valid = size if valid is None else min(valid, size)
        left = size
        pos = 0
        for c0, n in runs:
            if left <= 0:
                break
            length = min(n * self.cs, left)
            base = self.cluster_off(c0)
            p = 0
            while p < length:
                if stop is not None and stop.is_set():
                    return False
                m = min(CHUNK, length - p)
                real = max(0, min(m, valid - pos))
                out.write((self.read_abs(base + p, real) if real else b"") + bytes(m - real))
                p += m
                pos += m
            left -= length
        while left > 0:                       # cadena mas corta que el tamano: se rellena con ceros
            m = min(CHUNK, left)
            out.write(bytes(m))
            left -= m
        return True

    # ---------------- arbol (lazy)
    def scan(self, progress=None, stop=None):
        self._ent[5] = dict(name="", is_dir=True, size=0, mtime=0, c0=self.root_cluster, borrado=False,
                            parent=None, dlen=0)
        self._load_dir(5)
        if progress:
            progress(1, 1, len(self._kids.get(5, [])))
        return self.stats

    def _load_dir(self, node):
        if node in self._kids or node not in self._ent:
            return
        try:
            items = self._leer_dir(node, self._ent[node])
        except Exception as ex:
            self.log(f"AVISO: no pude leer una carpeta: {ex!r}")
            items = []
        ids = []
        for d in items:
            self._next += 1
            i = self._next
            d["parent"] = node
            self._ent[i] = d
            self.tparent[i] = node
            ids.append(i)
        self._kids[node] = ids

    def children_of(self, node):
        c = self._ccache.get(node)
        if c is not None:
            return c
        self._load_dir(node)
        items = []
        for i in self._kids.get(node, []):
            e = self._ent[i]
            if e["borrado"] and not self.mostrar_borrados:
                continue
            items.append((i, e["name"], e["is_dir"], e["size"], e["mtime"], e["borrado"]))
        out = armar_entradas(items)
        self._ccache[node] = out
        return out

    def tiene_hijos(self, i):
        e = self._ent.get(i)
        if not e or not e["is_dir"]:
            return False
        if i in self._kids:
            return any(self._ent[k]["borrado"] <= self.mostrar_borrados for k in self._kids[i])
        return True

    def set_borrados(self, v):
        self.mostrar_borrados = bool(v)
        self._ccache = {}

    def es_borrado(self, i):
        e = self._ent.get(i)
        return bool(e and e["borrado"])

    def file_size(self, i):
        return self._ent[i]["size"]

    def find(self, path):
        node = self.ROOT
        for c in [c for c in path.replace("\\", "/").split("/") if c]:
            nxt = None
            for e in self.children_of(node):
                if e.name.lower() == c.lower():
                    nxt = e.id
                    break
            if nxt is None:
                return None
            node = nxt
        return node

    def info_borrado(self, i):
        e = self._ent.get(i)
        if not e or not e["borrado"]:
            return ""
        if e["is_dir"]:
            return "carpeta borrada"
        try:
            pct = self._runs_archivo(e)[3]
        except Exception:
            pct = None
        return texto_borrado(pct)

    # ---------------- copia
    def extract(self, i, dst, stop=None, force=False, mtime=0):
        e = self._ent[i]
        size = e["size"]
        dst = lp(dst)
        if not force and os.path.exists(dst) and os.path.getsize(dst) == size:
            return "SALTADO", size, 0
        runs, incompleto, nota, pct = self._runs_archivo(e)
        if size > 0 and not runs:
            return "SIN_DATOS", 0, 0
        if e["borrado"] and size > 0 and pct == 0:
            return "SOBRESCRITO", 0, 0
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        tmp = dst + ".partial"
        z0 = self.src.zero_filled
        try:
            with open(tmp, "wb") as out:
                ok = self._volcar(runs, size, out, stop, e.get("vdl"))
            if not ok:
                os.remove(tmp)
                return "DETENIDO", 0, 0
            os.replace(tmp, dst)
        except OSError as ex:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return "ERROR_ESCRITURA:" + str(ex), 0, 0
        if mtime:
            try:
                os.utime(dst, (mtime, mtime))
            except OSError:
                pass
        nbad = self.src.zero_filled - z0
        if e["borrado"] and pct is not None and pct < 100:
            nota = (nota + "; " if nota else "") + f"borrado: {pct}% de los clusters sin reutilizar"
            st = "PARCIAL"
        else:
            st = "PARCIAL" if nbad else ("INCOMPLETO" if incompleto else "OK")
        return st, size, nbad, nota


# --------------------------------------------------------------------------
# FAT32
# --------------------------------------------------------------------------
class Fat32Volume(_FsLazy):
    NOMBRE = "FAT32"
    _HI = True                      # FAT32 guarda la parte alta del cluster inicial (FAT16/12 no)

    def __init__(self, src, vol_off=0, vol_len=0, log=None):
        super().__init__(src, vol_off, vol_len, log)
        self._abrir()

    @staticmethod
    def parse_boot(b):
        if len(b) < 512 or b[82:90] != b"FAT32   ":
            return None
        bps, spc, rsv, nfats = struct.unpack_from("<HBHB", b, 0x0B)
        total = struct.unpack_from("<I", b, 0x20)[0] or struct.unpack_from("<H", b, 0x13)[0]
        fatsz, _fl, _ver, root = struct.unpack_from("<IHHI", b, 0x24)
        if bps not in (512, 1024, 2048, 4096) or spc not in (1, 2, 4, 8, 16, 32, 64, 128):
            return None
        if rsv < 1 or nfats not in (1, 2) or fatsz == 0 or root < 2 or total == 0:
            return None
        nclu = (total - rsv - nfats * fatsz) // spc
        if nclu < 1:
            return None
        return dict(bps=bps, spc=spc, rsv=rsv, nfats=nfats, fatsz=fatsz, root=root, nclu=nclu)

    def _abrir(self):
        for desc, off in (("sector de arranque", 0), ("copia de respaldo del arranque", 6 * 512)):
            g = self.parse_boot(self.read_abs(off, 512))
            if g:
                break
        else:
            raise NtfsError("No pude leer el sector de arranque FAT32 (ni su copia de respaldo).")
        self.bps, self.cs = g["bps"], g["bps"] * g["spc"]
        self.nfats = g["nfats"]
        self.fat_off = g["rsv"] * g["bps"]
        self.fat_stride = g["fatsz"] * g["bps"]
        self.data_off = (g["rsv"] + g["nfats"] * g["fatsz"]) * g["bps"]
        self.nclu = g["nclu"]
        self.root_cluster = g["root"]
        self.geom_origen = desc
        self.log(f"Formato FAT32 ({desc}) | cluster {fmt_size(self.cs)} | {self.nclu} clusters")

    # ---------------- carpetas
    def _leer_dir(self, node, ent):
        c0 = self.root_cluster if node == self.ROOT else ent["c0"]
        if c0 < 2 or c0 >= self.nclu + 2:
            return []
        if not ent["borrado"]:
            runs, _, _ = self._cadena(c0, None, 4096)
            data = self._leer_runs(runs)
        else:                                   # carpeta borrada: se asume contigua
            data = self.read_abs(self.cluster_off(c0), self.cs)
            if data[:11] != b".          " or (((struct.unpack_from("<H", data, 0x14)[0] << 16) if self._HI else 0) |
                                               struct.unpack_from("<H", data, 0x1A)[0]) != c0:
                return []                       # el cluster ya se reutilizo
            n = 1
            while n < 16 and not self._hay_fin(data[-self.cs:]) and c0 + n < self.nclu + 2:
                if self._libres_fat(c0 + n, 1) != 1:
                    break
                data += self.read_abs(self.cluster_off(c0 + n), self.cs)
                n += 1
        return self._parse_dir(data, ent["borrado"])

    @staticmethod
    def _hay_fin(bloque):
        return any(bloque[k] == 0 for k in range(0, len(bloque), 32))

    def _parse_dir(self, data, dir_borrado):
        out = []
        lfn = []
        vlen = self.nclu * self.cs
        for k in range(len(data) // 32):
            e = data[k * 32:(k + 1) * 32]
            b0 = e[0]
            if b0 == 0:
                break
            attr = e[11]
            if attr & 0x3F == 0x0F:
                lfn.append(e)
                continue
            if attr & 0x08:
                lfn = []
                continue
            n11 = bytes(e[0:11])
            if n11[:2] in (b". ", b"..") and n11.strip(b" .") == b"":
                lfn = []
                continue
            borrado = dir_borrado or b0 == 0xE5
            es_dir = bool(attr & 0x10)
            c0 = ((struct.unpack_from("<H", e, 0x14)[0] << 16) if self._HI else 0) | struct.unpack_from("<H", e, 0x1A)[0]
            size = struct.unpack_from("<I", e, 0x1C)[0]
            if borrado:                         # descartar basura de entradas viejas
                if attr & 0xC0 or any(c < 0x20 or c in b'"*+,/:;<=>?[\\]|' for c in n11[1:]):
                    lfn = []
                    continue
                if es_dir and size != 0 or size > vlen:
                    lfn = []
                    continue
                if not es_dir and size == 0:
                    lfn = []
                    continue
                if (size > 0 or es_dir) and not (2 <= c0 < self.nclu + 2):
                    lfn = []
                    continue
            # nombre
            nombre = None
            piezas = []
            if lfn:
                objetivo = lfn[-1][13]
                if b0 == 0xE5:          # la 1ra letra del nombre corto quedo pisada: se prueba cual encaja
                    ok_chk = any(_lfn_chk(bytes([c]) + n11[1:]) == objetivo for c in range(256))
                else:
                    ok_chk = _lfn_chk(n11) == objetivo
                if ok_chk:
                    for l in reversed(lfn):
                        if l[13] != objetivo:
                            break
                        piezas.append(l)
            if piezas:
                s = ""
                for l in piezas:
                    s += (bytes(l[1:11]) + bytes(l[14:26]) + bytes(l[28:32])).decode("utf-16le", "replace")
                nombre = s.split("\x00")[0].replace("\uffff", "")
            lfn = []
            if not nombre:
                base = bytearray(n11[:8])
                if b0 == 0x05:
                    base[0] = 0xE5
                elif b0 == 0xE5:
                    base[0] = ord("_")
                ext = n11[8:11]
                bs = bytes(base).decode("cp850", "replace").rstrip()
                es = ext.decode("cp850", "replace").rstrip()
                if e[12] & 0x08:
                    bs = bs.lower()
                if e[12] & 0x10:
                    es = es.lower()
                nombre = bs + ("." + es if es else "")
            out.append(dict(name=nombre, is_dir=es_dir, size=0 if es_dir else size,
                            mtime=dos_time(struct.unpack_from("<H", e, 0x18)[0], struct.unpack_from("<H", e, 0x16)[0]),
                            c0=c0, borrado=borrado, dlen=0))
        return out

    # ---------------- datos de un archivo
    def _libres_fat(self, c0, n):
        if n <= 0:
            return 0
        raw = self.read_abs(self.fat_off + c0 * 4, n * 4)[:n * 4]
        arr = array.array("I")
        arr.frombytes(raw)
        if sys.byteorder == "big":
            arr.byteswap()
        return arr.count(0)

    def _runs_archivo(self, e):
        """(runs, incompleto, nota, pct_sin_reutilizar o None)"""
        c0, size = e["c0"], e["size"]
        need = -(-size // self.cs) if size else 0
        if need == 0:
            return [], False, "", None
        if not (2 <= c0 < self.nclu + 2):
            return [], True, "sin cluster inicial", 0 if e["borrado"] else None
        if e["borrado"]:                        # la FAT ya no tiene la cadena: se asume contigua
            need = min(need, self.nclu + 2 - c0)
            libres = self._libres_fat(c0, need)
            return [(c0, need)], False, "se asumio archivo contiguo", int(round(100 * libres / need))
        runs, got, ok = self._cadena(c0, need)
        if got < need:
            runs = self._completar_contiguo(runs, got, need)
            return runs, True, "cadena de la FAT danada; se asumio contigua", None
        return runs, False, "", None


# --------------------------------------------------------------------------
# FAT16 / FAT12 (pendrives, tarjetas y discos viejos): raiz de tamano fijo y FAT de 16 o 12 bits
# --------------------------------------------------------------------------
class Fat16Volume(Fat32Volume):
    NOMBRE = "FAT16"
    _HI = False

    @staticmethod
    def parse_boot(b):
        """Valida un arranque FAT12/FAT16 (el tipo se decide por la cantidad de clusters, como indica Microsoft)."""
        if len(b) < 512 or b[510:512] != b"\x55\xaa" or b[0] not in (0xEB, 0xE9):
            return None
        bps, spc, rsv, nfats, rootn, tot16 = struct.unpack_from("<HBHBHH", b, 0x0B)
        fatsz = struct.unpack_from("<H", b, 0x16)[0]
        tot32 = struct.unpack_from("<I", b, 0x20)[0]
        total = tot16 or tot32
        if bps not in (512, 1024, 2048, 4096) or spc not in (1, 2, 4, 8, 16, 32, 64, 128):
            return None
        if rsv < 1 or nfats not in (1, 2) or fatsz == 0 or rootn == 0 or total == 0 or b[0x15] < 0xF0:
            return None
        if (rootn * 32) % bps:
            return None
        rootsec = (rootn * 32) // bps
        nclu = (total - rsv - nfats * fatsz - rootsec) // spc
        if nclu < 1 or nclu >= 65525:           # 65525 o mas clusters = FAT32
            return None
        if (nclu + 2) * (1.5 if nclu < 4085 else 2) > fatsz * bps + 1:
            return None                         # la FAT no alcanza para tantos clusters
        return dict(bps=bps, spc=spc, rsv=rsv, nfats=nfats, fatsz=fatsz, rootn=rootn, rootsec=rootsec,
                    total=total, nclu=nclu, tipo="FAT12" if nclu < 4085 else "FAT16")

    def _abrir(self):
        g = self.parse_boot(self.read_abs(0, 512))
        if not g:
            raise NtfsError("No pude leer el sector de arranque FAT16/FAT12 (esos formatos no guardan copia de respaldo).")
        self.bps, self.cs = g["bps"], g["bps"] * g["spc"]
        self.nfats = g["nfats"]
        self.fat_off = g["rsv"] * g["bps"]
        self.fat_stride = g["fatsz"] * g["bps"]
        self.root_off = (g["rsv"] + g["nfats"] * g["fatsz"]) * g["bps"]
        self.root_len = g["rootsec"] * g["bps"]
        self.data_off = self.root_off + self.root_len
        self.nclu = g["nclu"]
        self.root_cluster = 0
        self.tipo = g["tipo"]
        self.NOMBRE = g["tipo"]
        self._fatbuf = {}
        if self.tipo == "FAT12":
            self._EOC, self._BAD, self._MASK = 0xFF8, 0xFF7, 0xFFF
        else:
            self._EOC, self._BAD, self._MASK = 0xFFF8, 0xFFF7, 0xFFFF
        self.geom_origen = "sector de arranque"
        self.log(f"Formato {self.tipo} | cluster {fmt_size(self.cs)} | {self.nclu} clusters")

    def _tabla(self, copia):
        t = self._fatbuf.get(copia)
        if t is None:
            t = self.read_abs(self.fat_off + copia * self.fat_stride, self.fat_stride)
            self._fatbuf[copia] = t
        return t

    def _fat(self, c, copia=0):
        t = self._tabla(copia)
        if self.tipo == "FAT12":
            o = c + (c >> 1)
            if o + 2 > len(t):
                return 0
            v = t[o] | (t[o + 1] << 8)
            return (v >> 4) if c & 1 else (v & 0xFFF)
        o = c * 2
        if o + 2 > len(t):
            return 0
        return t[o] | (t[o + 1] << 8)

    def _libres_fat(self, c0, n):
        if n <= 0:
            return 0
        if self.tipo == "FAT12":
            return sum(1 for c in range(c0, c0 + n) if self._fat(c) == 0)
        t = self._tabla(0)[c0 * 2:(c0 + n) * 2]
        arr = array.array("H")
        arr.frombytes(t[:(len(t) // 2) * 2])
        if sys.byteorder == "big":
            arr.byteswap()
        return arr.count(0)

    def _leer_dir(self, node, ent):
        if node == self.ROOT:                   # la raiz es una zona fija, no una cadena de clusters
            return self._parse_dir(self.read_abs(self.root_off, self.root_len), False)
        return super()._leer_dir(node, ent)

    def scan(self, progress=None, stop=None):
        self._ent[5] = dict(name="", is_dir=True, size=0, mtime=0, c0=0, borrado=False, parent=None, dlen=0)
        self._load_dir(5)
        if progress:
            progress(1, 1, len(self._kids.get(5, [])))
        return self.stats


# --------------------------------------------------------------------------
# exFAT
# --------------------------------------------------------------------------
class ExFatVolume(_FsLazy):
    NOMBRE = "exFAT"
    _EOC = 0xFFFFFFF8
    _BAD = 0xFFFFFFF7
    _MASK = 0xFFFFFFFF

    def __init__(self, src, vol_off=0, vol_len=0, log=None):
        super().__init__(src, vol_off, vol_len, log)
        self._bm = None
        self._bm_tried = False
        self._bm_info = None
        self._abrir()

    @staticmethod
    def parse_boot(b):
        if len(b) < 512 or b[3:11] != b"EXFAT   ":
            return None
        sh_b, sh_c, nfats = b[0x6C], b[0x6D], b[0x6E]
        if not (9 <= sh_b <= 12) or sh_c > 25 - sh_b:
            return None
        fat_off, fat_len, heap_off, nclu, root = struct.unpack_from("<IIIII", b, 0x50)
        if nclu == 0 or fat_off == 0 or heap_off == 0 or not (2 <= root < nclu + 2):
            return None
        return dict(sh_b=sh_b, sh_c=sh_c, nfats=max(1, nfats), fat_off=fat_off, fat_len=fat_len,
                    heap_off=heap_off, nclu=nclu, root=root)

    def _abrir(self):
        g = self.parse_boot(self.read_abs(0, 512))
        desc = "sector de arranque"
        if not g:
            for sh in (9, 10, 11, 12):
                g = self.parse_boot(self.read_abs(12 << sh, 512))
                if g:
                    desc = "copia de respaldo del arranque"
                    break
        if not g:
            raise NtfsError("No pude leer el sector de arranque exFAT (ni su copia de respaldo).")
        bps = 1 << g["sh_b"]
        self.bps, self.cs = bps, bps << g["sh_c"]
        self.nfats = g["nfats"]
        self.fat_off = g["fat_off"] * bps
        self.fat_stride = g["fat_len"] * bps
        self.data_off = g["heap_off"] * bps
        self.nclu = g["nclu"]
        self.root_cluster = g["root"]
        self.geom_origen = desc
        self.log(f"Formato exFAT ({desc}) | cluster {fmt_size(self.cs)} | {self.nclu} clusters")

    # ---------------- mapa de bits de clusters libres
    def _bitmap(self):
        if not self._bm_tried:
            self._bm_tried = True
            try:
                if self._bm_info is None:
                    self._load_dir(self.ROOT)
                if self._bm_info:
                    c0, ln = self._bm_info
                    need = -(-ln // self.cs)
                    runs, got, _ = self._cadena(c0, need)
                    runs = self._completar_contiguo(runs, got, need)
                    self._bm = self._leer_runs(runs, ln)[:ln]
            except Exception:
                self._bm = None
        return self._bm

    def _libres_runs(self, runs):
        bm = self._bitmap()
        if bm is None:
            return None
        libres = total = 0
        for c0, n in runs:
            total += n
            libres += n - bits_set(bm, c0 - 2, n)
        return libres, total

    # ---------------- carpetas
    def _leer_dir(self, node, ent):
        borr = ent["borrado"]
        if node == self.ROOT:
            runs, _, _ = self._cadena(self.root_cluster, None, 4096)
        else:
            c0, dlen = ent["c0"], ent.get("dlen", 0)
            if not (2 <= c0 < self.nclu + 2) or dlen <= 0 or dlen > (64 << 20):
                return []
            need = -(-dlen // self.cs)
            if ent.get("nofat"):
                runs = [(c0, need)]
            else:
                runs, got, ok = self._cadena(c0, need)
                if got < need:
                    runs = self._completar_contiguo(runs, got, need) if borr else runs
        return self._parse_dir(self._leer_runs(runs), borr, node == self.ROOT)

    def _parse_dir(self, data, dir_borrado, es_raiz):
        out = []
        n = len(data) // 32
        k = 0
        vlen = self.nclu * self.cs
        while k < n:
            e = data[k * 32:(k + 1) * 32]
            t = e[0]
            if t == 0x00:
                break
            if t == 0x81 and es_raiz:
                self._bm_info = (struct.unpack_from("<I", e, 20)[0], struct.unpack_from("<Q", e, 24)[0])
            if t not in (0x85, 0x05):
                k += 1
                continue
            cnt = e[1]
            if cnt < 2 or k + cnt >= n:
                k += 1
                continue
            st = data[(k + 1) * 32:(k + 2) * 32]
            if st[0] not in (0xC0, 0x40):
                k += 1
                continue
            borrado = dir_borrado or t == 0x05
            attr = struct.unpack_from("<H", e, 4)[0]
            mod = struct.unpack_from("<I", e, 12)[0]
            flags, nlen = st[1], st[3]
            vdl = struct.unpack_from("<Q", st, 8)[0]
            c0 = struct.unpack_from("<I", st, 20)[0]
            dlen = struct.unpack_from("<Q", st, 24)[0]
            es_dir = bool(attr & 0x10)
            nombres = [data[(k + 2 + j) * 32:(k + 3 + j) * 32] for j in range(cnt - 1)]
            valido = nlen >= 1 and len(nombres) * 15 >= nlen and all(x[0] in (0xC1, 0x41) for x in nombres)
            if valido and borrado:
                if dlen > vlen or (dlen > 0 and not (2 <= c0 < self.nclu + 2)) or attr & 0xFFC0:
                    valido = False
                if not es_dir and dlen == 0:
                    valido = False
            if valido:
                nombre = b"".join(bytes(x[2:32]) for x in nombres).decode("utf-16le", "replace")[:nlen]
                out.append(dict(name=nombre, is_dir=es_dir, size=0 if es_dir else dlen,
                                mtime=dos_time(mod >> 16, mod & 0xFFFF), c0=c0, borrado=borrado,
                                nofat=bool(flags & 2), dlen=dlen, vdl=min(vdl, dlen) if not es_dir else None))
            k += 1 + cnt
        return out

    # ---------------- datos de un archivo
    def _runs_archivo(self, e):
        c0, size = e["c0"], e["size"]
        need = -(-size // self.cs) if size else 0
        if need == 0:
            return [], False, "", None
        if not (2 <= c0 < self.nclu + 2):
            return [], True, "sin cluster inicial", 0 if e["borrado"] else None
        need = min(need, self.nclu + 2 - c0)
        incompleto, nota = False, ""
        if e.get("nofat"):
            runs = [(c0, need)]
        else:
            runs, got, ok = self._cadena(c0, need)
            if got < need:
                runs = self._completar_contiguo(runs, got, need)
                if e["borrado"]:
                    runs, nota = [(c0, need)], "se asumio archivo contiguo"
                else:
                    incompleto, nota = True, "cadena de la FAT danada; se asumio contigua"
        pct = None
        if e["borrado"]:
            r = self._libres_runs(runs)
            if r and r[1]:
                pct = int(round(100 * r[0] / r[1]))
        return runs, incompleto, nota, pct


def detectar_fs(src, off):
    """'ntfs', 'exfat', 'fat32' o 'fat16' (incluye FAT12) segun el sector de arranque (o sus copias de respaldo)."""
    b = src.read(off, 512)
    if b[3:11] == b"NTFS    ":
        return "ntfs"
    if b[3:11] == b"EXFAT   ":
        return "exfat"
    if b[82:90] == b"FAT32   ":
        return "fat32"
    if Fat16Volume.parse_boot(b):
        return "fat16"
    for sh in (9, 10, 11, 12):
        if src.read(off + (12 << sh), 512)[3:11] == b"EXFAT   ":
            return "exfat"
    if src.read(off + 6 * 512, 512)[82:90] == b"FAT32   ":
        return "fat32"
    return "ntfs"       # el camino NTFS prueba ademas sus copias y ubicaciones tipicas


# --------------------------------------------------------------------------
# Busqueda por contenido (carving): encuentra archivos por su firma, sin necesitar nombres
# --------------------------------------------------------------------------
class _Win:
    """Ventana de lectura sobre un archivo que empieza en 'start' dentro del origen."""
    BLK = 1 << 20

    def __init__(self, src, start, limit):
        self.src, self.start, self.limit = src, start, limit
        self.base = -1
        self.buf = b""

    def get(self, i, n):
        """n bytes desde el desplazamiento i del archivo (menos si se acaba el origen)."""
        a = self.start + i
        if i < 0 or a >= self.limit:
            return b""
        n = min(n, self.limit - a)
        if n <= 0:
            return b""
        if self.base >= 0 and self.base <= a and a + n <= self.base + len(self.buf):
            o = a - self.base
            return self.buf[o:o + n]
        if n >= self.BLK:
            return self.src.read(a, n)
        self.base = a
        self.buf = self.src.read(a, min(self.BLK, self.limit - a))
        return self.buf[:n]


def _buscar(w, pat, i, maxsz):
    while i < maxsz:
        blk = w.get(i, 1 << 20)
        if not blk:
            return None
        k = blk.find(pat)
        if k >= 0:
            return i + k
        if len(blk) < len(pat):
            return None
        i += len(blk) - len(pat) + 1
    return None


_RX_MARK = re.compile(rb"\xff[^\x00\xd0-\xd7\xff]")
_SOF = (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF)


def _len_jpeg(w, maxsz):
    if w.get(0, 3) != b"\xff\xd8\xff":
        return None
    i, sof, sos = 2, False, False
    while i < maxsz:
        b = w.get(i, 4)
        if len(b) < 2 or b[0] != 0xFF:
            return None
        m = b[1]
        if m == 0xFF:
            i += 1
            continue
        if m == 0xD9:
            return (i + 2, None) if (sof and sos) else None
        if m == 0x01 or 0xD0 <= m <= 0xD8:
            i += 2
            continue
        if len(b) < 4:
            return None
        L = (b[2] << 8) | b[3]
        if L < 2:
            return None
        if m in _SOF:
            sof = True
        i += 2 + L
        if m == 0xDA:                           # datos comprimidos hasta el proximo marcador real
            sos = True
            while True:
                if i >= maxsz:
                    return None
                blk = w.get(i, 65536)
                if not blk:
                    return None
                mm = _RX_MARK.search(blk)
                if mm:
                    i += mm.start()
                    break
                i += max(1, len(blk) - 1)
    return None


def _len_png(w, maxsz):
    if w.get(0, 8) != b"\x89PNG\r\n\x1a\n":
        return None
    i, first = 8, True
    while i < maxsz:
        h = w.get(i, 8)
        if len(h) < 8:
            return None
        L = struct.unpack(">I", h[:4])[0]
        t = h[4:8]
        if not all(65 <= c <= 90 or 97 <= c <= 122 for c in t):
            return None
        if first:
            if t != b"IHDR" or L != 13:
                return None
            first = False
        i += 12 + L
        if t == b"IEND":
            return i, None
        if L > maxsz:
            return None
    return None


def _gif_sub(w, i, maxsz):
    while i < maxsz:
        b = w.get(i, 1)
        if not b:
            return None
        i += 1 + b[0]
        if b[0] == 0:
            return i
    return None


def _len_gif(w, maxsz):
    h = w.get(0, 13)
    if len(h) < 13 or h[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    i = 13 + (3 * (2 << (h[10] & 7)) if h[10] & 0x80 else 0)
    while i < maxsz:
        b = w.get(i, 1)
        if not b:
            return None
        if b[0] == 0x3B:
            return i + 1, None
        if b[0] == 0x21:
            i = _gif_sub(w, i + 2, maxsz)
        elif b[0] == 0x2C:
            d = w.get(i + 1, 9)
            if len(d) < 9:
                return None
            i += 10 + (3 * (2 << (d[8] & 7)) if d[8] & 0x80 else 0) + 1
            i = _gif_sub(w, i, maxsz)
        else:
            return None
        if i is None:
            return None
    return None


def _len_bmp(w, maxsz):
    h = w.get(0, 30)
    if len(h) < 30 or h[:2] != b"BM":
        return None
    size, r1, r2, off, hs = struct.unpack_from("<IHHII", h, 2)
    if r1 or r2 or hs not in (12, 40, 52, 56, 64, 108, 124) or not (54 <= off < size <= maxsz):
        return None
    if hs >= 40:
        wd, ht = struct.unpack_from("<ii", h, 18)
        if wd <= 0 or wd > 30000 or ht == 0 or abs(ht) > 30000:
            return None
    return size, None


def _len_pdf(w, maxsz):
    if w.get(0, 5) != b"%PDF-":
        return None
    i, fin = 5, None
    for _ in range(64):
        j = _buscar(w, b"%%EOF", i, maxsz)
        if j is None:
            break
        end = j + 5
        ctx = w.get(max(0, j - 40), min(j, 40))
        mm = re.search(rb"startxref\s+(\d+)\s*$", ctx)
        valido = False
        if mm:
            x = int(mm.group(1))
            if 0 < x < j:
                t = w.get(x, 24)
                valido = t[:4] == b"xref" or re.match(rb"\d+\s+\d+\s+obj", t) is not None
        if valido:
            fin = end
            nxt = w.get(end, 24).lstrip(b"\r\n \t")
            if not (nxt[:4] == b"xref" or re.match(rb"\d+\s+\d+\s+obj", nxt)):
                break
        i = end
    if fin is None:
        return None
    fin += len(re.match(rb"[\r\n]{0,2}", w.get(fin, 2)).group())
    return fin, None


def _zip_nombres(w, off, sz, n):
    cd = w.get(off, min(sz, 1 << 20))
    out, p = [], 0
    for _ in range(min(n, 400)):
        if cd[p:p + 4] != b"PK\x01\x02" or p + 46 > len(cd):
            break
        nl, el, cl = struct.unpack_from("<HHH", cd, p + 28)
        out.append(cd[p + 46:p + 46 + nl].decode("cp437", "replace"))
        p += 46 + nl + el + cl
    return out


def _zip_ext(w, nombres):
    s = set(nombres)
    if "[Content_Types].xml" in s:
        if any(n.startswith("word/") for n in s):
            return "docx"
        if any(n.startswith("xl/") for n in s):
            return "xlsx"
        if any(n.startswith("ppt/") for n in s):
            return "pptx"
        return "zip"
    if nombres and nombres[0] == "mimetype":
        h = w.get(0, 30)
        if len(h) == 30:
            nl, el = struct.unpack_from("<HH", h, 26)
            mt = w.get(30 + nl + el, 80)
            for clave, ext in ((b"opendocument.text", "odt"), (b"opendocument.spreadsheet", "ods"),
                               (b"opendocument.presentation", "odp"), (b"epub", "epub")):
                if clave in mt:
                    return ext
    if "AndroidManifest.xml" in s:
        return "apk"
    if "META-INF/MANIFEST.MF" in s:
        return "jar"
    return "zip"


def _len_zip(w, maxsz):
    if w.get(0, 4) != b"PK\x03\x04":
        return None
    i = 4
    for _ in range(256):
        j = _buscar(w, b"PK\x05\x06", i, maxsz)
        if j is None:
            return None
        e = w.get(j, 22)
        if len(e) == 22:
            n, sz, off, cl = struct.unpack_from("<HIIH", e, 10)
            if n > 0 and off + sz == j and w.get(off, 4) == b"PK\x01\x02":
                return j + 22 + cl, _zip_ext(w, _zip_nombres(w, off, sz, n))
        i = j + 4
    return None


def _len_7z(w, maxsz):
    h = w.get(0, 32)
    if len(h) < 32 or h[:6] != b"7z\xbc\xaf\x27\x1c":
        return None
    if zlib.crc32(h[12:32]) & 0xFFFFFFFF != struct.unpack_from("<I", h, 8)[0]:
        return None
    off, size = struct.unpack_from("<QQ", h, 12)
    L = 32 + off + size
    return (L, None) if size > 0 and L <= maxsz else None


_BOX_OK = {b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"moof", b"mfra", b"styp",
           b"sidx", b"pdin", b"meta", b"udta", b"junk", b"pnot", b"mfro", b"prft", b"ssix"}
_BRAND = {b"crx ": "cr3", b"qt  ": "mov", b"M4A ": "m4a", b"M4V ": "m4v", b"M4B ": "m4a", b"heic": "heic", b"heix": "heic",
          b"mif1": "heic", b"avif": "avif", b"3g2a": "3g2"}


def _len_mp4(w, maxsz):
    h = w.get(0, 12)
    if len(h) < 12 or h[4:8] != b"ftyp":
        return None
    brand = h[8:12]
    i, vistos = 0, set()
    while i < maxsz:
        b = w.get(i, 16)
        if len(b) < 8:
            break
        size, t = struct.unpack(">I", b[:4])[0], b[4:8]
        if t not in _BOX_OK:
            break
        if size == 1:
            if len(b) < 16:
                break
            size = struct.unpack(">Q", b[8:16])[0]
        if size < 8 or i + size > maxsz:
            break
        vistos.add(t)
        i += size
    if not ({b"moov", b"moof"} & vistos) or i < 1000:
        return None
    ext = "3gp" if brand[:3] == b"3gp" else _BRAND.get(brand, "mp4")
    return i, ext


def _len_riff(w, maxsz):
    h = w.get(0, 12)
    if len(h) < 12 or h[:4] != b"RIFF":
        return None
    size = struct.unpack("<I", h[4:8])[0]
    ext = {b"AVI ": "avi", b"WAVE": "wav", b"WEBP": "webp"}.get(h[8:12])
    if not ext or size < 36 or size + 8 > maxsz:
        return None
    return size + 8 + (size & 1), ext


def _len_sqlite(w, maxsz):
    h = w.get(0, 100)
    if len(h) < 100 or h[:16] != b"SQLite format 3\x00":
        return None
    ps = struct.unpack(">H", h[16:18])[0]
    ps = 65536 if ps == 1 else ps
    pages = struct.unpack(">I", h[28:32])[0]
    if ps < 512 or ps & (ps - 1) or pages == 0 or ps * pages > maxsz:
        return None
    return ps * pages, None


_BR1 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
_BR2 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0]
_SR = {3: [44100, 48000, 32000], 2: [22050, 24000, 16000], 0: [11025, 12000, 8000]}


def _mp3_frame(h):
    if len(h) < 4 or h[0] != 0xFF or (h[1] & 0xE0) != 0xE0:
        return None
    ver, layer = (h[1] >> 3) & 3, (h[1] >> 1) & 3
    if ver == 1 or layer != 1:
        return None
    br, sr, pad = (h[2] >> 4) & 15, (h[2] >> 2) & 3, (h[2] >> 1) & 1
    if br in (0, 15) or sr == 3:
        return None
    bitrate = (_BR1 if ver == 3 else _BR2)[br] * 1000
    return (144 if ver == 3 else 72) * bitrate // _SR[ver][sr] + pad


def _len_mp3(w, maxsz):
    h = w.get(0, 10)
    i, minimo = 0, 200
    if h[:3] == b"ID3":
        if len(h) < 10 or any(b & 0x80 for b in h[6:10]):
            return None
        i = 10 + ((h[6] << 21) | (h[7] << 14) | (h[8] << 7) | h[9]) + (10 if h[5] & 0x10 else 0)
        minimo = 20
    frames = 0
    while i < maxsz:
        f = _mp3_frame(w.get(i, 4))
        if not f:
            break
        i += f
        frames += 1
    if frames < minimo:
        return None
    if w.get(i, 3) == b"TAG":
        i += 128
    return i, None


def _len_ole(w, maxsz):
    h = w.get(0, 512)
    if len(h) < 512 or h[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return None
    ss = 1 << struct.unpack_from("<H", h, 30)[0]
    if ss not in (512, 4096):
        return None
    nfat, dir0, difat0, ndifat = struct.unpack_from("<IIII", h, 44)[0], struct.unpack_from("<I", h, 48)[0], \
        struct.unpack_from("<I", h, 68)[0], struct.unpack_from("<I", h, 72)[0]
    if not (0 < nfat <= 4096):
        return None
    lista = [s for s in struct.unpack_from("<109I", h, 76) if s < 0xFFFFFFFA]
    s = difat0
    while s < 0xFFFFFFFA and ndifat > 0 and len(lista) < nfat:
        d = w.get((s + 1) * ss, ss)
        if len(d) < ss:
            return None
        lista += [x for x in struct.unpack_from("<%dI" % (ss // 4 - 1), d, 0) if x < 0xFFFFFFFA]
        s = struct.unpack_from("<I", d, ss - 4)[0]
        ndifat -= 1
    fat = []
    for s in lista[:nfat]:
        d = w.get((s + 1) * ss, ss)
        if len(d) < ss:
            return None
        fat += struct.unpack("<%dI" % (ss // 4), d)
    ult = max((k for k, v in enumerate(fat) if v != 0xFFFFFFFF), default=-1)
    if ult < 0 or dir0 >= len(fat):
        return None
    L = (ult + 2) * ss
    if L > maxsz:
        return None
    nombres, s, n = set(), dir0, 0                     # que tipo de documento es
    while s < len(fat) and n < 16:
        d = w.get((s + 1) * ss, ss)
        for k in range(0, len(d) - 127, 128):
            nl = struct.unpack_from("<H", d, k + 64)[0]
            if 2 <= nl <= 64:
                nombres.add(d[k:k + nl - 2].decode("utf-16le", "replace"))
        s = fat[s]
        n += 1
    ext = "ole"
    if "WordDocument" in nombres:
        ext = "doc"
    elif "Workbook" in nombres or "Book" in nombres:
        ext = "xls"
    elif "PowerPoint Document" in nombres:
        ext = "ppt"
    return L, ext


def _vint(b, i):
    first = b[i]
    n, mask = 1, 0x80
    while n <= 8 and not (first & mask):
        n += 1
        mask >>= 1
    if n > 8 or i + n > len(b):
        return None
    v = first & (mask - 1)
    unk = v == mask - 1
    for k in range(1, n):
        v = (v << 8) | b[i + k]
        unk = unk and b[i + k] == 0xFF
    return v, n, unk


def _len_mkv(w, maxsz):
    h = w.get(0, 96)
    if h[:4] != b"\x1a\x45\xdf\xa3":
        return None
    r = _vint(h, 4)
    if not r or r[2]:
        return None
    pos = 4 + r[1] + r[0]
    s = w.get(pos, 16)
    if s[:4] != b"\x18\x53\x80\x67":
        return None
    r2 = _vint(s, 4)
    if not r2 or r2[2]:
        return None
    L = pos + 4 + r2[1] + r2[0]
    return (L, "webm" if b"webm" in h else "mkv") if L <= maxsz else None


# ---- TIFF y RAW de camara basados en TIFF (CR2, NEF, ARW, DNG, ORF, RW2, PEF): el largo sale de las IFD
_TIFF_TAM = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4, 16: 8, 17: 8, 18: 8}
_TIFF_MAGIC = (42, 0x4F52, 0x5352, 0x55)       # TIFF/DNG/CR2/NEF/ARW, ORF (2 variantes), RW2


def _len_tiff(w, maxsz):
    h = w.get(0, 16)
    if len(h) < 16 or h[:2] not in (b"II", b"MM"):
        return None
    e = "<" if h[:2] == b"II" else ">"
    magic = struct.unpack(e + "H", h[2:4])[0]
    if magic not in _TIFF_MAGIC:
        return None
    ifd0 = struct.unpack(e + "I", h[4:8])[0]
    if ifd0 < 8 or ifd0 + 2 > maxsz:
        return None
    fin = 8
    cola, vistos = [ifd0], set()
    hay_basico, marca, dng = False, b"", False
    while cola:
        off = cola.pop(0)
        if off == 0 or off in vistos:
            continue
        if off < 8 or off + 2 > maxsz or len(vistos) >= 64:
            return None
        vistos.add(off)
        b = w.get(off, 2)
        if len(b) < 2:
            return None
        n = struct.unpack(e + "H", b)[0]
        if n == 0 or n > 2000:
            return None
        ent = w.get(off + 2, n * 12 + 4)
        if len(ent) < n * 12 + 4:
            return None
        fin = max(fin, off + 2 + n * 12 + 4)
        tags = {}
        for k in range(n):
            tag, typ, cnt = struct.unpack(e + "HHI", ent[k * 12:k * 12 + 8])
            tsz = _TIFF_TAM.get(typ)
            if tsz is None or cnt > (1 << 22):
                return None
            tam = tsz * cnt
            raw = ent[k * 12 + 8:k * 12 + 12]
            if tam > 4:
                voff = struct.unpack(e + "I", raw)[0]
                if voff < 8 or voff + tam > maxsz:
                    return None
                fin = max(fin, voff + tam)
                tags[tag] = (typ, cnt, voff, None)
            else:
                tags[tag] = (typ, cnt, None, raw)

        def valores(tag):
            t = tags.get(tag)
            if not t:
                return []
            typ, cnt, voff, raw = t
            if typ not in (3, 4, 8, 9, 16):
                return []
            tsz = _TIFF_TAM[typ]
            data = raw[:tsz * cnt] if raw is not None else w.get(voff, tsz * cnt)
            if len(data) < tsz * cnt:
                return []
            f = {2: "H", 4: "I", 8: "Q"}[tsz]
            return list(struct.unpack(e + f * cnt, data))

        if off == ifd0:
            hay_basico = any(t in tags for t in (0x0100, 0x0101, 0x0111, 0x0102, 0x0103))
            if 0x010F in tags and tags[0x010F][0] == 2:
                typ, cnt, voff, raw = tags[0x010F]
                marca = (raw if raw is not None else w.get(voff, min(cnt, 32)))[:32].upper()
            dng = 0xC612 in tags
        for ot, bc in ((0x0111, 0x0117), (0x0144, 0x0145)):        # tiras y teselas de la imagen
            offs, cnts = valores(ot), valores(bc)
            if offs and cnts and len(offs) == len(cnts):
                for o, c in zip(offs, cnts):
                    if o + c > maxsz:
                        return None
                    fin = max(fin, o + c)
            elif len(offs) == 1 and not cnts:
                fin = max(fin, offs[0])
        jo, jl = valores(0x0201), valores(0x0202)                  # miniatura JPEG
        if jo and jl:
            if jo[0] + jl[0] > maxsz:
                return None
            fin = max(fin, jo[0] + jl[0])
        for tag in (0x014A, 0x8769, 0x8825, 0xA005):                # SubIFD, Exif, GPS, interoperabilidad
            for v in valores(tag):
                cola.append(v)
        cola.append(struct.unpack(e + "I", ent[n * 12:n * 12 + 4])[0])     # siguiente IFD de la cadena
    if fin > maxsz or fin < 1024:
        return None
    if magic == 0x55:
        ext = "rw2"
    elif magic in (0x4F52, 0x5352):
        ext = "orf"
    elif not hay_basico:
        return None
    elif h[8:10] == b"CR" and e == "<":
        ext = "cr2"
    elif dng:
        ext = "dng"
    elif marca.startswith(b"NIKON"):
        ext = "nef"
    elif marca.startswith(b"SONY"):
        ext = "arw"
    elif marca.startswith((b"PENTAX", b"RICOH")):
        ext = "pef"
    else:
        ext = "tif"
    return fin, ext


def _len_raf(w, maxsz):                       # RAW de Fujifilm: tabla de offsets/largos en la cabecera
    h = w.get(0, 108)
    if len(h) < 108 or h[:16] != b"FUJIFILMCCD-RAW ":
        return None
    fin = 108
    for k in (84, 92, 100):
        o, l = struct.unpack(">II", h[k:k + 8])
        if o and (o < 108 or o + l > maxsz):
            return None
        fin = max(fin, o + l)
    return (fin, None) if fin > 108 else None


def _len_psd(w, maxsz):                       # Photoshop (PSD y PSB)
    h = w.get(0, 26)
    if len(h) < 26 or h[:4] != b"8BPS" or h[6:12] != bytes(6):
        return None
    ver, chans, alto, ancho, prof, modo = struct.unpack(">HxxxxxxHIIHH", h[4:26])
    if ver not in (1, 2) or not 1 <= chans <= 56 or prof not in (1, 8, 16, 32) or modo > 9:
        return None
    if alto == 0 or ancho == 0 or alto > (300000 if ver == 2 else 30000) or ancho > (300000 if ver == 2 else 30000):
        return None
    i = 26
    for k in range(3):                         # modo de color, recursos de imagen, capas y mascaras
        big = (k == 2 and ver == 2)
        b = w.get(i, 8 if big else 4)
        if len(b) < (8 if big else 4):
            return None
        n = struct.unpack(">Q" if big else ">I", b)[0]
        i += (8 if big else 4) + n
        if i > maxsz:
            return None
    c = w.get(i, 2)
    if len(c) < 2:
        return None
    comp = struct.unpack(">H", c)[0]
    i += 2
    fila = (ancho * prof + 7) // 8
    if comp == 0:
        i += chans * alto * fila
    elif comp == 1:                            # RLE: tabla de largos por linea y luego los datos
        sz = 4 if ver == 2 else 2
        n = chans * alto
        t = w.get(i, n * sz) if n * sz < (64 << 20) else b""
        if len(t) < n * sz:
            return None
        i += n * sz + sum(struct.unpack(">" + ("I" if sz == 4 else "H") * n, t))
    else:
        return None                            # ZIP: el largo no se puede deducir
    return (i, "psb" if ver == 2 else "psd") if i <= maxsz else None


def _vint5(b, i):
    r = s = 0
    while i < len(b) and s < 70:
        x = b[i]
        r |= (x & 0x7F) << s
        i += 1
        if not x & 0x80:
            return r, i
        s += 7
    return None, i


def _len_rar(w, maxsz):
    h = w.get(0, 8)
    if h[:7] == b"Rar!\x1a\x07\x00":          # RAR 1.5 - 4.x
        i, ult, archivos = 7, 7, 0
        while i < maxsz:
            b = w.get(i, 11)
            if len(b) < 7:
                break
            crc, tipo, fl, sz = struct.unpack("<HBHH", b[:7])
            if tipo < 0x72 or tipo > 0x7B or sz < 7 or sz > 65535:
                break
            cab = w.get(i, sz)
            if len(cab) < sz or (zlib.crc32(cab[2:]) & 0xFFFF) != crc:
                break
            tot = sz + (struct.unpack("<I", cab[7:11])[0] if fl & 0x8000 and sz >= 11 else 0)
            if i + tot > maxsz:
                break
            i += tot
            ult = i
            archivos += tipo == 0x74
            if tipo == 0x7B:
                return (i, None) if archivos else None
        return (ult, None) if archivos else None
    if h[:8] == b"Rar!\x1a\x07\x01\x00":      # RAR 5
        i, ult, archivos = 8, 8, 0
        while i < maxsz:
            b = w.get(i, 64)
            if len(b) < 8:
                break
            crc = struct.unpack("<I", b[:4])[0]
            hs, j = _vint5(b, 4)
            if hs is None or hs < 2 or hs > 1 << 20:
                break
            cab = w.get(i + 4, (j - 4) + hs)
            if len(cab) < (j - 4) + hs or zlib.crc32(cab) & 0xFFFFFFFF != crc:
                break
            tipo, k = _vint5(cab, j - 4)
            fl, k = _vint5(cab, k)
            if tipo is None or fl is None:
                break
            if fl & 1:
                _, k = _vint5(cab, k)
            datos = 0
            if fl & 2:
                datos, k = _vint5(cab, k)
                if datos is None:
                    break
            tot = j + hs + datos
            if i + tot > maxsz:
                break
            i += tot
            ult = i
            archivos += tipo in (2, 3)
            if tipo == 5:
                return (i, None) if archivos else None
        return (ult, None) if archivos else None
    return None


# ---- Reconstruccion de JPEG fragmentados (JPEG baseline/secuencial de 8 bits)
def _jpeg_cabecera(b):
    """Lee la cabecera JPEG hasta SOS. Devuelve dict o None si no es un JPEG secuencial que sepamos validar."""
    n = len(b)
    if b[:3] != b"\xff\xd8\xff":
        return None
    i, dht, sof, dri, comps, qdc = 2, {}, None, 0, None, {}
    while i + 4 <= n:
        if b[i] != 0xFF:
            return None
        m = b[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m == 0x01 or 0xD0 <= m <= 0xD8:
            i += 2
            continue
        if m == 0xD9:
            return None
        L = (b[i + 2] << 8) | b[i + 3]
        seg = b[i + 4:i + 2 + L]
        if len(seg) < L - 2 or L < 2:
            return None
        if m == 0xC4:
            k = 0
            while k + 17 <= len(seg):
                tc, th = seg[k] >> 4, seg[k] & 15
                cnt = list(seg[k + 1:k + 17])
                tot = sum(cnt)
                sy = list(seg[k + 17:k + 17 + tot])
                if tc > 1 or th > 3 or len(sy) < tot:
                    return None
                dht[(tc, th)] = (cnt, sy)
                k += 17 + tot
        elif m == 0xDB:
            k = 0
            while k < len(seg):
                pq, tq = seg[k] >> 4, seg[k] & 15
                tam = 129 if pq else 65
                if k + tam > len(seg):
                    return None
                qdc[tq] = ((seg[k + 1] << 8) | seg[k + 2]) if pq else seg[k + 1]
                k += tam
        elif m in (0xC0, 0xC1):
            if len(seg) < 6 or seg[0] != 8:
                return None
            alto, ancho, nf = (seg[1] << 8) | seg[2], (seg[3] << 8) | seg[4], seg[5]
            if alto == 0 or ancho == 0 or nf not in (1, 3, 4) or len(seg) < 6 + 3 * nf:
                return None
            comps = [(seg[6 + 3 * c], seg[7 + 3 * c] >> 4, seg[7 + 3 * c] & 15) for c in range(nf)]
            if any(h < 1 or h > 4 or v < 1 or v > 4 for _, h, v in comps):
                return None
            sof = (alto, ancho)
        elif m in (0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            return None                         # progresivo / sin perdida / aritmetico: no se valida
        elif m == 0xDD and len(seg) >= 2:
            dri = (seg[0] << 8) | seg[1]
        elif m == 0xDA:
            if sof is None or not seg:
                return None
            ns = seg[0]
            if ns != len(comps) or len(seg) < 1 + 2 * ns + 3 or tuple(seg[1 + 2 * ns:4 + 2 * ns]) != (0, 63, 0):
                return None                     # solo escaneo unico entrelazado
            alto, ancho = sof
            hmax = max(h for _, h, _ in comps)
            vmax = max(v for _, _, v in comps)
            if ns == 1:
                mx, my, bloques = -(-ancho // 8), -(-alto // 8), [0]
                orden = [(0, seg[2] >> 4, seg[2] & 15)]
            else:
                mx, my = -(-ancho // (8 * hmax)), -(-alto // (8 * vmax))
                orden = []
                for c in range(ns):
                    cid, tt = seg[1 + 2 * c], seg[2 + 2 * c]
                    ci = next((k for k, (i_, _, _) in enumerate(comps) if i_ == cid), None)
                    if ci is None:
                        return None
                    for _ in range(comps[ci][1] * comps[ci][2]):
                        orden.append((ci, tt >> 4, tt & 15))
            tablas = []
            for ci, td, ta in orden:
                tablas.append((ci, _huff_tabla(dht.get((0, td))), _huff_tabla(dht.get((1, ta)))))
            if any(t[1] is None or t[2] is None for t in tablas):
                return None
            # cota del DC cuantizado de cada componente: el DC real esta en [-1024, 1016] y se divide por el paso q
            cota = []
            for ci in range(len(comps)):
                q = qdc.get(comps[ci][2])
                cota.append(1024 // q + 2 if q else 2047)
            return dict(ini=i + 2 + L, total=mx * my, dri=dri, bloques=tablas, ncomp=len(comps), cota=cota)
        i += 2 + L
    return None


def _huff_tabla(t):
    """Tabla de busqueda de 16 bits: entrada = (largo << 8) | simbolo, 0 si el codigo no existe."""
    if not t:
        return None
    cnt, sy = t
    tabla = [0] * 65536
    code = k = 0
    for ln in range(1, 17):
        for _ in range(cnt[ln - 1]):
            lo = code << (16 - ln)
            hi = lo + (1 << (16 - ln))
            if hi > 65536 or k >= len(sy):
                return None
            tabla[lo:hi] = [(ln << 8) | sy[k]] * (hi - lo)
            k += 1
            code += 1
        code <<= 1
    return tabla


_JS_OK, _JS_ERR, _JS_MAS = 0, 1, 2


def _jpeg_decodificar(inf, data, st, snaps=None, snap_cada=1024, maxmcu=None):
    """Decodifica (solo los codigos, sin IDCT) el escaneo de 'data' desde el estado 'st'.
    st = (pos, acc, nb, mcu, preds, pads). Devuelve (estado, st_ultimo_mcu, pos_error_o_fin).
      OK  : se decodificaron todos los MCU y sigue un EOI justo donde corresponde; pos = fin del archivo
      ERR : codigo invalido, coeficiente fuera de rango, marcador inesperado...
      MAS : los datos se acabaron sin errores (hay que leer mas)."""
    pos, acc, nb, mcu, preds, pads = st
    preds = list(preds)
    total, dri, bloques, cota = inf["total"], inf["dri"], inf["bloques"], inf["cota"]
    if maxmcu is not None:
        total = min(total, maxmcu)
    n = len(data)
    prox = pos
    ult = (pos, acc, nb, mcu, tuple(preds), pads)
    while mcu < total:
        if dri and mcu and mcu % dri == 0:
            if pads == 0 and pos + 2 > n:
                return _JS_MAS, ult, pos
            nb = 0
            acc = 0
            pads = 0
            if pos + 2 > n:
                return _JS_MAS, ult, pos
            if data[pos] != 0xFF or data[pos + 1] != 0xD0 + ((mcu // dri) - 1) % 8:
                return _JS_ERR, ult, pos
            pos += 2
            preds = [0] * len(preds)
        if pos >= prox and snaps is not None:
            ult = (pos, acc & ((1 << nb) - 1), nb, mcu, tuple(preds), pads)
            snaps.append(ult)
            prox = pos + snap_cada
        else:
            ult = (pos, acc & ((1 << nb) - 1), nb, mcu, tuple(preds), pads) if snaps is None else ult
        acc &= (1 << nb) - 1
        for ci, tdc, tac in bloques:
            # ---- DC
            while nb < 16:
                if pos >= n:
                    return _JS_MAS, ult, pos
                b = data[pos]
                if b == 0xFF:
                    if pos + 1 >= n:
                        return _JS_MAS, ult, pos
                    if data[pos + 1] == 0:
                        pos += 2
                    else:
                        acc <<= 8
                        nb += 8
                        pads += 8
                        continue
                else:
                    pos += 1
                acc = (acc << 8) | b
                nb += 8
            e = tdc[(acc >> (nb - 16)) & 0xFFFF]
            if not e:
                return _JS_ERR, ult, pos
            nb -= e >> 8
            cat = e & 255
            if cat:
                if cat > 11:
                    return _JS_ERR, ult, pos
                while nb < cat:
                    if pos >= n:
                        return _JS_MAS, ult, pos
                    b = data[pos]
                    if b == 0xFF:
                        if pos + 1 >= n:
                            return _JS_MAS, ult, pos
                        if data[pos + 1] == 0:
                            pos += 2
                        else:
                            acc <<= 8
                            nb += 8
                            pads += 8
                            continue
                    else:
                        pos += 1
                    acc = (acc << 8) | b
                    nb += 8
                nb -= cat
                v = (acc >> nb) & ((1 << cat) - 1)
                if v < (1 << (cat - 1)):
                    v -= (1 << cat) - 1
                v += preds[ci]
                if v < -cota[ci] or v > cota[ci]:
                    return _JS_ERR, ult, pos
                preds[ci] = v
            # ---- AC
            k = 1
            while k < 64:
                while nb < 16:
                    if pos >= n:
                        return _JS_MAS, ult, pos
                    b = data[pos]
                    if b == 0xFF:
                        if pos + 1 >= n:
                            return _JS_MAS, ult, pos
                        if data[pos + 1] == 0:
                            pos += 2
                        else:
                            acc <<= 8
                            nb += 8
                            pads += 8
                            continue
                    else:
                        pos += 1
                    acc = (acc << 8) | b
                    nb += 8
                e = tac[(acc >> (nb - 16)) & 0xFFFF]
                if not e:
                    return _JS_ERR, ult, pos
                nb -= e >> 8
                rs = e & 255
                s = rs & 15
                if s == 0:
                    if rs == 0xF0:
                        k += 16
                        continue
                    if rs:
                        return _JS_ERR, ult, pos
                    break
                k += rs >> 4
                if k > 63:
                    return _JS_ERR, ult, pos
                if nb < s:
                    while nb < s:
                        if pos >= n:
                            return _JS_MAS, ult, pos
                        b = data[pos]
                        if b == 0xFF:
                            if pos + 1 >= n:
                                return _JS_MAS, ult, pos
                            if data[pos + 1] == 0:
                                pos += 2
                            else:
                                acc <<= 8
                                nb += 8
                                pads += 8
                                continue
                        else:
                            pos += 1
                        acc = (acc << 8) | b
                        nb += 8
                nb -= s
                k += 1
            if pads and nb < pads:                    # leyo mas alla del marcador que cierra los datos
                return _JS_ERR, ult, pos
        mcu += 1
        acc &= (1 << nb) - 1
    # ---- fin: lo que sobra de bits debe ser relleno y luego tiene que venir el EOI
    if maxmcu is not None and mcu < inf["total"]:
        return _JS_MAS, ult, pos
    real = nb - pads if pads else nb
    if real < 0 or real >= 8 or ((acc >> pads) & ((1 << real) - 1)) != (1 << real) - 1:
        return _JS_ERR, ult, pos
    if pads:
        fin = pos
    else:
        fin = pos
        if fin + 2 > n:
            return _JS_MAS, ult, pos
    if data[fin:fin + 2] != b"\xff\xd9":
        if fin + 2 > n:
            return _JS_MAS, ult, pos
        return _JS_ERR, ult, pos
    return _JS_OK, ult, fin + 2


def reconstruir_jpeg(src, a, limite, unidad=4096, rangos=None, evitar=None, stop=None, ventana=32 << 20,
                     tiempo=45.0, max_frag=8, trabajo_max=96 << 20):
    """Intenta rearmar un JPEG fragmentado cuya cabecera esta en 'a' (inicio de un cluster de 'unidad' bytes).
    Decodifica los datos hasta que dejan de ser validos (alli termina el primer fragmento) y busca, hacia
    adelante, el cluster que los continua: el bueno es el que sigue decodificando sin errores y termina en un EOI
    justo despues del ultimo MCU. Devuelve dict(frags=[(offset_abs, largo)], length) o None.
    rangos: [(inicio, largo)] donde puede estar el resto (p. ej. el espacio libre); evitar(offset)->True para
    saltar zonas ya usadas por otros archivos."""
    t0 = time.time()
    trabajo = [0]
    hdr = src.read(a, min(1 << 18, limite - a))
    inf = _jpeg_cabecera(hdr)
    if not inf:
        return None
    ini = inf["ini"]
    prim = bytearray(src.read(a + ini, min(ventana, limite - a - ini)))
    starts = sorted(rangos) if rangos else None
    ncomp = inf["ncomp"]

    def permitido(c):
        if evitar is not None and evitar(c):
            return False
        if starts is None:
            return True
        i = bisect.bisect_right([s for s, _ in starts], c) - 1
        return i >= 0 and starts[i][0] <= c and c + unidad <= starts[i][0] + starts[i][1]

    limite_t = [t0 + tiempo]

    def agotado():
        return (stop is not None and stop.is_set()) or time.time() > limite_t[0] or trabajo[0] > trabajo_max

    def analizar(L, segs, off, st, prof, cfg, pre=None):
        data = bytes(L[off:]) if off else bytes(L)
        snaps = []
        if pre is None:
            r, ult, p = _jpeg_decodificar(inf, data, st, snaps)
            trabajo[0] += len(data)
        else:
            r, ult, p, snaps = pre
        if r == _JS_OK:
            return segs, off + p
        if r == _JS_MAS or prof >= cfg["prof"]:
            return None
        e = off + p
        abs0, log0 = segs[-1]
        abs_err = abs0 + (e - log0)
        b0 = a + ((abs_err - a) // unidad) * unidad
        spos = [s[0] for s in snaps]
        # posibles puntos de corte: el cluster donde se detecto el error y algunos anteriores (si lo que sigue al
        # corte es otro JPEG con las mismas tablas, el error aparece bastante despues del corte real)
        puntos = []
        for k in range(cfg["K"]):
            B = b0 - k * unidad
            if B <= abs0:
                break
            cut = log0 + (B - abs0)
            j = bisect.bisect_right(spos, cut - off) - 1
            if j < 0:
                continue
            s0 = snaps[j]
            puntos.append((B, cut, (0, s0[1], s0[2], s0[3], s0[4], s0[5]), bytes(L[off + s0[0]:cut])))
        previo = cfg["previo0"]
        for tmax in cfg["tiers"]:                   # brechas de hasta N clusters, por tandas
            for B, cut, st0, tail in puntos:
                a_win = B + unidad + previo * unidad
                if a_win >= limite:
                    continue
                b_win = min(limite, B + unidad + min(tmax, 1 << 20) * unidad, a_win + ventana)
                win = src.read(a_win, b_win - a_win)
                for i in range(0, len(win) - unidad + 1, unidad):
                    if agotado():
                        return None
                    C = a_win + i
                    if not permitido(C):
                        continue
                    probe = tail + win[i:i + unidad]
                    trabajo[0] += len(probe)
                    r2, u2, p2 = _jpeg_decodificar(inf, probe, st0)
                    if r2 == _JS_OK:
                        return segs + [(C, cut)], cut + (p2 - len(tail))
                    if r2 != _JS_MAS:
                        continue
                    ext = src.read(C, min(ventana, limite - C))
                    sn2 = []
                    r3, u3, p3 = _jpeg_decodificar(inf, tail + ext, st0, None if cfg["terminal"] else sn2)
                    trabajo[0] += p3
                    if r3 == _JS_OK:
                        return segs + [(C, cut)], cut + (p3 - len(tail))
                    if not cfg["terminal"] and r3 == _JS_ERR and p3 - len(tail) >= 2 * unidad:
                        uso = p3 - len(tail)
                        L2 = bytearray(L[:cut]) + ext[:uso + 2 * unidad]
                        res = analizar(L2, segs + [(C, cut)], cut - len(tail), st0, prof + 1, cfg, (r3, u3, p3, sn2))
                        if res:
                            return res
            previo = min(tmax, 1 << 20)
        return None

    # tres pasadas de costo creciente: (A) un solo corte y brecha chica probando muchos cortes (datos "validos"
    # de otro JPEG en el hueco); (B) varios fragmentos y brechas grandes (pocos cortes); (C) un corte, brecha grande
    inicio = (0, 0, 0, 0, [0] * ncomp, 0)
    pasadas = [(0.15, dict(K=48, tiers=(64,), terminal=True, prof=1, previo0=0)),
               (0.60, dict(K=3, tiers=(64, 1024, 1 << 40), terminal=False, prof=max_frag, previo0=0)),
               (1.00, dict(K=48, tiers=(1024, 1 << 40), terminal=True, prof=1, previo0=64))]
    res = None
    for frac, cfg in pasadas:
        limite_t[0] = t0 + tiempo * frac
        if agotado():
            break
        res = analizar(prim, [(a + ini, 0)], 0, inicio, 0, cfg)
        if res:
            break
        if stop is not None and stop.is_set():
            return None
    if not res:
        return None
    segs, fin = res
    if len(segs) < 2:
        return None                               # sin fragmentos: lo resuelve el carving normal
    frags = []
    for k, (ab, lg) in enumerate(segs):
        fin_k = segs[k + 1][1] if k + 1 < len(segs) else fin
        frags.append((ab, fin_k - lg))
    frags[0] = (a, ini + frags[0][1])
    return dict(frags=frags, length=sum(n for _, n in frags))


EXT_GRUPO = {"jpg": "Fotos", "png": "Fotos", "gif": "Fotos", "bmp": "Fotos", "webp": "Fotos", "heic": "Fotos",
             "avif": "Fotos", "mp4": "Videos", "mov": "Videos", "m4v": "Videos", "3gp": "Videos", "3g2": "Videos",
             "avi": "Videos", "mkv": "Videos", "webm": "Videos", "mp3": "Audio", "m4a": "Audio", "wav": "Audio",
             "pdf": "Documentos", "docx": "Documentos", "xlsx": "Documentos", "pptx": "Documentos",
             "doc": "Documentos", "xls": "Documentos", "ppt": "Documentos", "odt": "Documentos",
             "ods": "Documentos", "odp": "Documentos", "epub": "Documentos", "ole": "Documentos",
             "zip": "Comprimidos", "7z": "Comprimidos", "jar": "Comprimidos", "apk": "Comprimidos",
             "sqlite": "Bases de datos", "tif": "Fotos", "cr2": "Fotos", "cr3": "Fotos", "nef": "Fotos",
             "arw": "Fotos", "dng": "Fotos", "orf": "Fotos", "rw2": "Fotos", "pef": "Fotos", "raf": "Fotos",
             "psd": "Fotos", "psb": "Fotos", "rar": "Comprimidos"}
GRUPOS_CARVING = ("Fotos", "Videos", "Audio", "Documentos", "Comprimidos", "Bases de datos")
_GB = 1 << 30
# (extension por defecto, firma, desplazamiento de la firma, funcion que mide el archivo, tamano maximo)
SIGS = [("jpg", b"\xff\xd8\xff", 0, _len_jpeg, 200 << 20), ("png", b"\x89PNG\r\n\x1a\n", 0, _len_png, 200 << 20),
        ("gif", b"GIF8", 0, _len_gif, 100 << 20), ("bmp", b"BM", 0, _len_bmp, 300 << 20),
        ("pdf", b"%PDF-", 0, _len_pdf, 1 * _GB), ("zip", b"PK\x03\x04", 0, _len_zip, 2 * _GB),
        ("7z", b"7z\xbc\xaf\x27\x1c", 0, _len_7z, 4 * _GB), ("mp4", b"ftyp", 4, _len_mp4, 16 * _GB),
        ("avi", b"RIFF", 0, _len_riff, 4 * _GB), ("sqlite", b"SQLite format 3\x00", 0, _len_sqlite, 4 * _GB),
        ("mp3", b"ID3", 0, _len_mp3, 500 << 20), ("mp3", b"\xff\xfb", 0, _len_mp3, 500 << 20),
        ("mp3", b"\xff\xf3", 0, _len_mp3, 500 << 20), ("mp3", b"\xff\xf2", 0, _len_mp3, 500 << 20),
        ("doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, _len_ole, 1 * _GB),
        ("mkv", b"\x1a\x45\xdf\xa3", 0, _len_mkv, 16 * _GB),
        ("tif", b"II*\x00", 0, _len_tiff, 500 << 20), ("tif", b"MM\x00*", 0, _len_tiff, 500 << 20),
        ("orf", b"IIRO", 0, _len_tiff, 500 << 20), ("orf", b"IIRS", 0, _len_tiff, 500 << 20),
        ("rw2", b"IIU\x00", 0, _len_tiff, 500 << 20),
        ("raf", b"FUJIFILMCCD-RAW ", 0, _len_raf, 500 << 20), ("psd", b"8BPS", 0, _len_psd, 2 * _GB),
        ("rar", b"Rar!\x1a\x07", 0, _len_rar, 4 * _GB)]
# grupos que puede producir cada firma (el tipo exacto lo decide la funcion al medir el archivo)
_SIG_GRUPOS = {"jpg": {"Fotos"}, "png": {"Fotos"}, "gif": {"Fotos"}, "bmp": {"Fotos"},
               "pdf": {"Documentos"}, "zip": {"Documentos", "Comprimidos"}, "7z": {"Comprimidos"},
               "mp4": {"Videos", "Audio", "Fotos"}, "avi": {"Videos", "Audio", "Fotos"},
               "sqlite": {"Bases de datos"}, "mp3": {"Audio"}, "doc": {"Documentos"}, "mkv": {"Videos"},
               "tif": {"Fotos"}, "orf": {"Fotos"}, "rw2": {"Fotos"}, "raf": {"Fotos"}, "psd": {"Fotos"},
               "rar": {"Comprimidos"}}


def carve(src, rangos, limite, grupos=None, min_size=10240, stop=None, progress=None, log=None,
          reconstruir=False, unidad=4096):
    """Busca archivos por su contenido en los 'rangos' [(inicio, largo)] absolutos del origen.
    'limite' = ultimo byte legible. Con reconstruir=True intenta ademas rearmar los JPEG fragmentados
    (los fragmentos se buscan dentro de 'rangos'; 'unidad' = tamano de cluster). Devuelve (hallazgos, completo)."""
    grupos = set(GRUPOS_CARVING) if grupos is None else set(grupos)
    sigs = [s for s in SIGS if _SIG_GRUPOS[s[0]] & grupos]
    total = sum(l for _, l in rangos) or 1
    hits, hechos, skip_hasta = [], 0, -1
    ocupados = []                                 # [(inicio, fin)] de los fragmentos de JPEG ya rearmados
    BLOCK, OV = 8 << 20, 64

    def en_ocupado(x):
        return any(a0 <= x < b0 for a0, b0 in ocupados)
    for r0, rl in rangos:
        r_end = min(r0 + rl, limite)
        pos = -(-r0 // 512) * 512
        hechos += pos - r0
        while pos < r_end:
            if stop is not None and stop.is_set():
                return hits, False
            if pos < skip_hasta:                       # dentro de un archivo ya encontrado: saltar
                nuevo = min(-(-skip_hasta // 512) * 512, r_end)
                hechos += nuevo - pos
                pos = nuevo
                continue
            n = min(BLOCK, r_end - pos)
            blk = src.read(pos, min(n + OV, limite - pos))
            cands = []
            for ext, magic, moff, fn, maxsz in sigs:
                ml = len(magic)
                if ml >= 4:
                    k = blk.find(magic)
                    while k != -1:
                        if k >= moff and (k - moff) < n and (k - moff) % 512 == 0:
                            cands.append((pos + k - moff, ext, fn, maxsz))
                        k = blk.find(magic, k + 1)
                else:
                    for a0 in range(0, n, 512):
                        if blk[a0 + moff:a0 + moff + ml] == magic:
                            cands.append((pos + a0, ext, fn, maxsz))
            cands.sort(key=lambda x: x[0])
            for a, ext0, fn, maxsz in cands:
                if a < skip_hasta or (ocupados and en_ocupado(a)):
                    continue
                try:
                    res = fn(_Win(src, a, limite), min(maxsz, limite - a))
                except Exception:
                    res = None
                if not res and reconstruir and ext0 == "jpg":
                    try:
                        rc = reconstruir_jpeg(src, a, limite, unidad, rangos, en_ocupado, stop)
                    except Exception:
                        rc = None
                    if rc and rc["length"] >= min_size and "Fotos" in grupos:
                        hits.append(dict(off=a, length=rc["length"], ext="jpg", grupo="Fotos", frags=rc["frags"]))
                        skip_hasta = a + rc["frags"][0][1]
                        ocupados.extend((o, o + l) for o, l in rc["frags"][1:])
                        continue
                if not res:
                    continue
                L, ext = res
                ext = ext or ext0
                if L < min_size or a + L > limite or EXT_GRUPO.get(ext, "Documentos") not in grupos:
                    continue
                hits.append(dict(off=a, length=L, ext=ext, grupo=EXT_GRUPO.get(ext, "Documentos")))
                skip_hasta = a + L
            pos += n
            hechos += n
            if progress:
                progress(min(hechos, total), total, len(hits))
    if progress:
        progress(total, total, len(hits))
    return hits, True


class CarveVolume:
    """Volumen virtual con los archivos hallados por contenido (misma interfaz que los demas)."""
    ROOT = 5
    ORPHAN = -1
    NOMBRE = "Busqueda por contenido"

    def __init__(self, src, hits, log=None):
        self.src, self.hits = src, hits
        self.log = log or (lambda s: None)
        self.tparent = {5: None}
        self.mostrar_borrados = False
        self.skip_root = ()
        self.stats = {}
        self._grp = {}                 # id de carpeta -> nombre
        self._kids = {}
        self._fil = {}
        nombres = sorted({h["grupo"] for h in hits})
        gid = {n: 1000 + k for k, n in enumerate(nombres)}
        self._kids[5] = [gid[n] for n in nombres]
        for n in nombres:
            self._grp[gid[n]] = n
            self._kids[gid[n]] = []
            self.tparent[gid[n]] = 5
        for n, h in enumerate(hits):
            fid = 10000 + n
            self._fil[fid] = h
            self._kids[gid[h["grupo"]]].append(fid)
            self.tparent[fid] = gid[h["grupo"]]

    def children_of(self, node):
        out = []
        for i in self._kids.get(node, []):
            if i in self._grp:
                out.append(Entrada(i, self._grp[i], limpiar(self._grp[i]), True, 0, 0))
            else:
                h = self._fil[i]
                nom = f"recuperado_{i - 10000 + 1:05d}.{h['ext']}"
                out.append(Entrada(i, nom, nom, False, h["length"], 0))
        return out

    def tiene_hijos(self, i):
        return i in self._grp

    def info_fila(self, i):
        if i in self._grp:
            n = len(self._kids[i])
            return f"{n} archivo" + ("" if n == 1 else "s")
        h = self._fil.get(i)
        if h and h.get("frags"):
            return f"encontrado por contenido \u00B7 reconstruido de {len(h['frags'])} fragmentos"
        return f"encontrado por contenido \u00B7 inicio {h['off']}" if h else ""

    def file_size(self, i):
        return self._fil[i]["length"]

    def set_borrados(self, v):
        pass

    def es_borrado(self, i):
        return False

    def info_borrado(self, i):
        return ""

    def extract(self, i, dst, stop=None, force=False, mtime=0):
        h = self._fil[i]
        dst = lp(dst)
        if not force and os.path.exists(dst) and os.path.getsize(dst) == h["length"]:
            return "SALTADO", h["length"], 0
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        tmp = dst + ".partial"
        z0 = self.src.zero_filled
        try:
            with open(tmp, "wb") as out:
                p = 0
                for fo, fl in (h.get("frags") or [(h["off"], h["length"])]):
                    q = 0
                    while q < fl:
                        if stop is not None and stop.is_set():
                            break
                        m = min(CHUNK, fl - q)
                        out.write(self.src.read(fo + q, m))
                        q += m
                        p += m
                    if stop is not None and stop.is_set():
                        break
            if stop is not None and stop.is_set() and p < h["length"]:
                os.remove(tmp)
                return "DETENIDO", 0, 0
            os.replace(tmp, dst)
        except OSError as ex:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return "ERROR_ESCRITURA:" + str(ex), 0, 0
        nbad = self.src.zero_filled - z0
        return ("PARCIAL" if nbad else "OK"), h["length"], nbad


# --------------------------------------------------------------------------
# Espacio libre de un volumen (para buscar solo donde pueden estar archivos borrados)
# --------------------------------------------------------------------------
def bitmap_free_runs(bm, nbits):
    """Rangos (inicio_bit, cantidad) con bit = 0 en un mapa de bits (bit 0 = menos significativo)."""
    out, cur, pos = [], None, 0
    for m in re.finditer(rb"[^\xff]+", bm):
        a, b = m.start(), m.end()
        if cur is not None and a > pos:
            out.append((cur, pos * 8 - cur))
            cur = None
        for i in range(a, b):
            v = bm[i]
            if v == 0:
                if cur is None:
                    cur = i * 8
            else:
                for bit in range(8):
                    if v >> bit & 1:
                        if cur is not None:
                            out.append((cur, i * 8 + bit - cur))
                            cur = None
                    elif cur is None:
                        cur = i * 8 + bit
        pos = b
    if cur is not None:
        out.append((cur, (len(bm) * 8 if pos >= len(bm) else pos * 8) - cur))
    res = []
    for a, n in out:
        if a >= nbits:
            continue
        res.append((a, min(n, nbits - a)))
    return res


def rangos_libres(vol):
    """[(inicio_absoluto, largo)] de los clusters libres de un volumen NTFS, FAT32, FAT16/12 o exFAT."""
    if isinstance(vol, Fat16Volume):
        usado = bytes(1 if vol._fat(c) else 0 for c in range(vol.nclu + 2))
        res = []
        for m in re.finditer(rb"\x00+", usado):
            a, b = max(m.start(), 2), min(m.end(), vol.nclu + 2)
            if b > a:
                res.append((vol.vol_off + vol.cluster_off(a), (b - a) * vol.cs))
        return res
    if isinstance(vol, Fat32Volume):
        raw = vol.read_abs(vol.fat_off, (vol.nclu + 2) * 4)
        arr = array.array("I")
        arr.frombytes(raw[:(len(raw) // 4) * 4])
        if sys.byteorder == "big":
            arr.byteswap()
        usado = bytes(1 if x & 0x0FFFFFFF else 0 for x in arr)
        res = []
        for m in re.finditer(rb"\x00+", usado):
            a, b = max(m.start(), 2), min(m.end(), vol.nclu + 2)
            if b > a:
                res.append((vol.vol_off + vol.cluster_off(a), (b - a) * vol.cs))
        return res
    if isinstance(vol, ExFatVolume):
        bm = vol._bitmap()
        if bm is None:
            return None
        return [(vol.vol_off + vol.cluster_off(2 + a), n * vol.cs) for a, n in bitmap_free_runs(bm, vol.nclu)]
    bm = vol._cargar_bitmap()
    if bm is None:
        return None
    nbits = len(bm) * 8
    if vol.vol_len:
        nbits = min(nbits, vol.vol_len // vol.cs)
    return [(vol.vol_off + a * vol.cs, n * vol.cs) for a, n in bitmap_free_runs(bm, nbits)]


# --------------------------------------------------------------------------
# Particiones perdidas: busca sectores de arranque NTFS / FAT32 / exFAT en todo el disco
# --------------------------------------------------------------------------
def _boot_info(b):
    """(tipo, largo_en_bytes, bytes_por_sector, dist_copia) si parece un arranque valido, o None."""
    if len(b) < 512:
        return None
    if b[3:11] == b"NTFS    ":
        bps = struct.unpack_from("<H", b, 11)[0]
        spc, total = b[13], struct.unpack_from("<Q", b, 40)[0]
        mft = struct.unpack_from("<Q", b, 48)[0]
        if bps in (512, 1024, 2048, 4096) and spc in (1, 2, 4, 8, 16, 32, 64, 128) and total > 0 \
                and b[510:512] == b"\x55\xaa" and 0 < mft * spc < total:
            return "NTFS", (total + 1) * bps, bps, 0
    elif b[3:11] == b"EXFAT   ":
        g = ExFatVolume.parse_boot(b)
        if g:
            n = struct.unpack_from("<Q", b, 72)[0]
            if n > 0:
                return "exFAT", n * (1 << g["sh_b"]), 1 << g["sh_b"], 12
    elif b[82:90] == b"FAT32   ":
        g = Fat32Volume.parse_boot(b)
        if g:
            total = struct.unpack_from("<I", b, 0x20)[0] or struct.unpack_from("<H", b, 0x13)[0]
            return "FAT32", total * g["bps"], g["bps"], 6
    elif b[54:59] in (b"FAT16", b"FAT12", b"FAT  "):
        g = Fat16Volume.parse_boot(b)
        if g:
            return g["tipo"], g["total"] * g["bps"], g["bps"], 0
    return None


def _validar_boot(src, start, b, tipo, bps):
    """Comprueba que lo que describe el arranque realmente existe (descarta falsos positivos)."""
    try:
        if tipo == "NTFS":
            spc = b[13]
            for campo in (48, 56):
                mft = struct.unpack_from("<Q", b, campo)[0]
                if src.read(start + mft * spc * bps, 4) == b"FILE":
                    return True
            return False
        if tipo == "FAT32":
            g = Fat32Volume.parse_boot(b)
            d = src.read(start + g["rsv"] * bps, 4)
            return d[0] >= 0xF0 and d[1:3] == b"\xff\xff"
        if tipo in ("FAT16", "FAT12"):
            g = Fat16Volume.parse_boot(b)
            d = src.read(start + g["rsv"] * bps, 4)
            return d[0] >= 0xF0 and d[1] == 0xFF
        g = ExFatVolume.parse_boot(b)
        d = src.read(start + g["fat_off"] * bps, 4)
        return d[0] >= 0xF0 and d[1:3] == b"\xff\xff"
    except Exception:
        return False


def buscar_particiones(src, size, stop=None, progress=None):
    """Recorre todo el origen buscando particiones NTFS/FAT32/FAT16/FAT12/exFAT. Devuelve [dict(offset, length, fs, nota)]."""
    BL, OV = 8 << 20, 512
    cand = {}
    pos = 0
    while pos < size:
        if stop is not None and stop.is_set():
            break
        n = min(BL, size - pos)
        blk = src.read(pos, min(n + OV, size - pos))
        for magic, mo in ((b"NTFS    ", 3), (b"EXFAT   ", 3), (b"FAT32   ", 82), (b"FAT16   ", 54), (b"FAT12   ", 54), (b"FAT     ", 54)):
            k = blk.find(magic)
            while k != -1:
                s0 = k - mo
                if s0 >= 0 and s0 < n and s0 % 512 == 0:
                    bi = _boot_info(blk[s0:s0 + 512])
                    if bi:
                        cand[pos + s0] = (bi, blk[s0:s0 + 512])
                k = blk.find(magic, k + 1)
        pos += n
        if progress:
            progress(min(pos, size), size, len(cand))
    res = {}
    MIB = 2048 * 512
    for a0, ((tipo, largo, bps, dcopia), b) in sorted(cand.items()):
        # (1) es la copia de respaldo de un arranque que ya encontramos: se ignora
        if dcopia and cand.get(a0 - dcopia * bps, ((None,),))[0][0] == tipo:
            continue
        if tipo == "NTFS" and cand.get(a0 + bps - largo, ((None,),))[0][0] == "NTFS":
            continue
        # (2) arranque principal o copia suelta (el principal se perdio): se deduce donde empieza
        start, nota = a0, ""
        if tipo == "NTFS":
            st2 = a0 + bps - largo
            if st2 >= 0 and st2 % 512 == 0 and (a0 + largo > size or (st2 % MIB == 0 and a0 % MIB != 0)):
                start, nota = st2, "sector de arranque perdido (se uso su copia)"
        elif dcopia:
            st2 = a0 - dcopia * bps
            if st2 >= 0 and st2 % MIB == 0 and a0 % MIB != 0:
                start, nota = st2, "sector de arranque perdido (se uso su copia)"
        if start < 0 or start % 512 or not _validar_boot(src, start, b, tipo, bps):
            continue
        res[start] = dict(offset=start, length=largo, fs=tipo, nota=nota)
    out = sorted(res.values(), key=lambda p: p["offset"])
    # lo que queda totalmente dentro de otra particion encontrada es una estructura vieja o una imagen
    fin = []
    for p in out:
        if any(q is not p and q["offset"] < p["offset"] and p["offset"] + p["length"] <= q["offset"] + q["length"]
               for q in out):
            continue
        fin.append(p)
    return fin


# --------------------------------------------------------------------------
# Copia segura de un disco a una imagen (para no seguir forzando un disco fallando)
# --------------------------------------------------------------------------
def clonar(src, dest, off, length, stop=None, progress=None, reanudar=True, bloque=1 << 20):
    """Copia [off, off+length) del origen a 'dest'. Los sectores ilegibles quedan en ceros y se anotan en
    'dest.malos.txt'. Si 'dest' ya existe y reanudar=True, sigue desde donde quedo."""
    pos, modo = 0, "wb"
    huella = hashlib.md5(src.read(off, 65536)).hexdigest()      # los primeros 64 KB identifican al disco
    ident = f"{os.path.abspath(getattr(src, 'path', ''))}|{off}|{length}|{huella}"
    meta = dest + ".origen"
    if reanudar and os.path.exists(dest):
        try:
            with open(meta, encoding="utf-8") as f:
                mismo = f.read().strip() == ident
        except OSError:
            mismo = False
        if mismo:                      # solo se continua si la copia anterior era de este mismo origen
            ya = os.path.getsize(dest)
            pos = min(ya - ya % bloque, length)
            modo = "r+b"
    with open(meta, "w", encoding="utf-8") as f:
        f.write(ident)
    t0 = time.time()
    base = pos
    estado = "completo"
    with open(dest, modo) as out:
        out.seek(pos)
        while pos < length:
            if stop is not None and stop.is_set():
                estado = "detenido"
                break
            n = min(bloque, length - pos)
            out.write(src.read(off + pos, n))
            pos += n
            if progress:
                progress(pos, length, len(src.bad), (pos - base) / max(time.time() - t0, 1e-6))
        if estado == "completo":
            out.truncate(length)
    malos = {s * SECTOR - off for s in src.bad if off <= s * SECTOR < off + length}
    if modo == "r+b" and os.path.exists(dest + ".malos.txt"):      # sumar los de la vez anterior
        with open(dest + ".malos.txt", encoding="utf-8") as f:
            for linea in f:
                if linea.strip().isdigit() and int(linea) < pos:
                    malos.add(int(linea))
    malos = sorted(malos)
    if malos:
        with open(dest + ".malos.txt", "w", encoding="utf-8") as f:
            f.write("# sectores de 512 bytes que no se pudieron leer (quedaron en ceros)\n")
            f.write("# desplazamiento_en_bytes_desde_el_inicio_de_la_copia\n")
            for m in malos:
                f.write(f"{m}\n")
    return dict(estado=estado, copiado=pos, malos=malos)


# --------------------------------------------------------------------------
# Clonado por fases (estilo ddrescue): primero lo sano y rapido, despues lo dificil
# --------------------------------------------------------------------------
# Estados de cada zona en el mapa: '+' copiada, '?' sin intentar, '*' fallo un bloque grande (sin recortar),
# '/' recortada pero sin raspar sector por sector, '-' sector ilegible.
class MapaClon:
    """Mapa de estados del clonado (se guarda en 'dest.mapa' para poder parar y seguir)."""

    def __init__(self, length):
        self.length = length
        self.r = [(0, length, "?")] if length else []

    def get(self, pos):
        i = bisect.bisect_right([a for a, _, _ in self.r], pos) - 1
        return self.r[i][2] if i >= 0 else "?"

    def set(self, a, n, st):
        if n <= 0:
            return
        b, out = a + n, []
        for x, l, e in self.r:
            y = x + l
            if y <= a or x >= b:
                out.append((x, l, e))
                continue
            if x < a:
                out.append((x, a - x, e))
            if y > b:
                out.append((b, y - b, e))
        out.append((a, n, st))
        out.sort()
        fus = []
        for x, l, e in out:                      # unir zonas contiguas con el mismo estado
            if fus and fus[-1][2] == e and fus[-1][0] + fus[-1][1] == x:
                fus[-1] = (fus[-1][0], fus[-1][1] + l, e)
            else:
                fus.append((x, l, e))
        self.r = fus

    def zonas(self, st):
        return [(a, n) for a, n, e in self.r if e == st]

    def total(self, st):
        return sum(n for a, n, e in self.r if e == st)

    def guardar(self, path):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("# mapa de clonado de Reflota: inicio_en_bytes largo estado\n")
            f.write("# estados: + copiado, ? sin intentar, * fallo en bloque grande, / sin raspar, - sector ilegible\n")
            f.write(f"{self.length}\n")
            for a, n, e in self.r:
                f.write(f"{a} {n} {e}\n")
        os.replace(tmp, path)

    @classmethod
    def cargar(cls, path, length):
        try:
            with open(path, encoding="utf-8") as f:
                lin = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            if int(lin[0]) != length:
                return None
            m = cls(length)
            m.r = []
            for l in lin[1:]:
                a, n, e = l.split()
                m.r.append((int(a), int(n), e))
            m.r.sort()
            if sum(n for _, n, _ in m.r) != length or any(e not in "+?*/-" for _, _, e in m.r):
                return None
            return m
        except (OSError, ValueError, IndexError):
            return None


def clonar_fases(src, dest, off, length, stop=None, progress=None, reanudar=True, bloque=1 << 20,
                 reintentos=1, tiempo_guardado=5.0):
    """Copia [off, off+length) del origen a 'dest' por fases, para forzar lo menos posible un disco que falla:
      1) copiar: bloques grandes hacia adelante; si uno falla se salta una distancia creciente (queda para despues)
         y las zonas saltadas se copian despues hacia atras;
      2) recortar: de cada bloque fallido se rescatan los bordes sector por sector hasta el primer error;
      3) raspar: lo que quedo en el medio se lee sector por sector;
      4) reintentar: los sectores ilegibles se vuelven a intentar 'reintentos' veces.
    Los sectores que nunca se leyeron quedan en ceros y se anotan en 'dest.malos.txt'. El avance se guarda en
    'dest.mapa': si se para (o se corta la luz) se sigue exactamente desde ahi.
    progress(hecho, total, malos, bytes_por_seg, fase). Devuelve dict(estado, copiado, malos, fase)."""
    SEC = SECTOR
    huella = hashlib.md5(src.read(off, 65536)).hexdigest()
    ident = f"{os.path.abspath(getattr(src, 'path', ''))}|{off}|{length}|{huella}"
    meta, mapa_p = dest + ".origen", dest + ".mapa"
    mapa = None
    if reanudar and os.path.exists(dest) and os.path.exists(mapa_p):
        try:
            with open(meta, encoding="utf-8") as f:
                mismo = f.read().strip() == ident
        except OSError:
            mismo = False
        if mismo:
            mapa = MapaClon.cargar(mapa_p, length)
    modo = "r+b" if mapa else "wb"
    if mapa is None:
        mapa = MapaClon(length)
    with open(meta, "w", encoding="utf-8") as f:
        f.write(ident)
    t0, ult_g, hecho0 = time.time(), time.time(), mapa.total("+")
    estado = {"fase": "copiar", "alto": False}

    def avisar(force=False):
        if progress:
            ok = mapa.total("+") + mapa.total("-")
            progress(ok, length, mapa.total("-") // SEC, (mapa.total("+") - hecho0) / max(time.time() - t0, 1e-6),
                     estado["fase"])

    def parar():
        return stop is not None and stop.is_set()

    def guardar_si_toca(force=False):
        nonlocal ult_g
        if force or time.time() - ult_g > tiempo_guardado:
            out.flush()
            mapa.guardar(mapa_p)
            ult_g = time.time()

    with open(dest, modo) as out:
        if modo == "wb":
            out.truncate(length)

        def leer(pos, n):
            """bytes o None si fallo."""
            try:
                return src.read_strict(off + pos, n)
            except OSError:
                return None

        def poner(pos, datos):
            out.seek(pos)
            out.write(datos)

        # ---- fase 1: copiar (adelante con saltos; luego atras lo saltado)
        salto = 0
        pos = 0
        pend = mapa.zonas("?")
        for a0, n0 in pend:                       # zonas sin intentar, en orden
            pos = a0
            fin = a0 + n0
            while pos < fin and not estado["alto"]:
                if parar():
                    estado["alto"] = True
                    break
                n = min(bloque, fin - pos)
                d = leer(pos, n)
                if d is not None:
                    poner(pos, d)
                    mapa.set(pos, n, "+")
                    salto = 0
                    pos += n
                else:
                    mapa.set(pos, n, "*")
                    pos += n
                    salto = bloque if salto == 0 else min(salto * 2, 1 << 30)
                    sal = min(salto, fin - pos)
                    pos += sal                    # lo saltado sigue '?' y se copia despues
                guardar_si_toca()
                avisar()
            if estado["alto"]:
                break
        if not estado["alto"]:
            for a0, n0 in reversed(mapa.zonas("?")):      # lo saltado, ahora hacia atras
                pos = a0 + n0
                while pos > a0:
                    if parar():
                        estado["alto"] = True
                        break
                    n = min(bloque, pos - a0)
                    p = pos - n
                    d = leer(p, n)
                    if d is not None:
                        poner(p, d)
                        mapa.set(p, n, "+")
                    else:
                        mapa.set(p, n, "*")
                    pos = p
                    guardar_si_toca()
                    avisar()
                if estado["alto"]:
                    break
        # ---- fase 2: recortar los bloques fallidos desde los dos bordes
        if not estado["alto"]:
            estado["fase"] = "recortar"
            for a0, n0 in mapa.zonas("*"):
                a, b = a0, a0 + n0
                while a < b:                      # desde el inicio hasta el primer error
                    if parar():
                        estado["alto"] = True
                        break
                    d = leer(a, SEC)
                    if d is None:
                        break
                    poner(a, d)
                    mapa.set(a, SEC, "+")
                    a += SEC
                while b > a and not estado["alto"]:   # desde el final hacia atras
                    if parar():
                        estado["alto"] = True
                        break
                    d = leer(b - SEC, SEC)
                    if d is None:
                        break
                    poner(b - SEC, d)
                    mapa.set(b - SEC, SEC, "+")
                    b -= SEC
                if a < b:
                    mapa.set(a, b - a, "/" if not estado["alto"] else "*")
                guardar_si_toca()
                avisar()
                if estado["alto"]:
                    break
        # ---- fase 3: raspar sector por sector
        if not estado["alto"]:
            estado["fase"] = "raspar"
            for a0, n0 in mapa.zonas("/"):
                p = a0
                while p < a0 + n0:
                    if parar():
                        estado["alto"] = True
                        break
                    d = leer(p, SEC)
                    if d is not None:
                        poner(p, d)
                        mapa.set(p, SEC, "+")
                    else:
                        mapa.set(p, SEC, "-")
                    p += SEC
                    guardar_si_toca()
                    avisar()
                if estado["alto"]:
                    break
        # ---- fase 4: reintentar los sectores ilegibles
        if not estado["alto"]:
            estado["fase"] = "reintentar"
            for vuelta in range(max(0, reintentos)):
                for a0, n0 in mapa.zonas("-"):
                    for p in range(a0, a0 + n0, SEC):
                        if parar():
                            estado["alto"] = True
                            break
                        d = leer(p, SEC)
                        if d is not None:
                            poner(p, d)
                            mapa.set(p, SEC, "+")
                        avisar()
                    if estado["alto"]:
                        break
                if estado["alto"] or not mapa.zonas("-"):
                    break
        guardar_si_toca(True)
    pendiente = length - mapa.total("+") - mapa.total("-")
    completo = not estado["alto"] and pendiente == 0
    malos = []
    for a0, n0 in mapa.zonas("-"):                # sectores confirmados como ilegibles (quedaron en ceros)
        malos.extend(range(a0 - a0 % SEC, a0 + n0, SEC))
    if completo and malos:
        with open(dest + ".malos.txt", "w", encoding="utf-8") as f:
            f.write("# sectores de 512 bytes que no se pudieron leer (quedaron en ceros)\n")
            f.write("# desplazamiento_en_bytes_desde_el_inicio_de_la_copia\n")
            for m in malos:
                f.write(f"{m}\n")
    elif completo and os.path.exists(dest + ".malos.txt"):
        os.remove(dest + ".malos.txt")
    avisar()
    return dict(estado="completo" if completo else "detenido", copiado=mapa.total("+") + mapa.total("-"),
                malos=malos, fase=estado["fase"], pendiente=pendiente)


# --------------------------------------------------------------------------
# Busqueda por nombre dentro de un volumen ya leido (sin importar si el archivo esta borrado)
# --------------------------------------------------------------------------
def _norm(s):
    """Minusculas y sin acentos, para que 'Facturación' coincida con 'facturacion'."""
    return "".join(c for c in unicodedata.normalize("NFD", s.casefold()) if not unicodedata.combining(c))


def hacer_filtro(consulta):
    """Funcion nombre->bool. Con * o ? se usa como patron ('*.pdf', 'foto_??.jpg'); si no, todas las
    palabras escritas deben aparecer en el nombre. Devuelve None si la consulta esta vacia."""
    q = _norm(consulta.strip())
    if not q:
        return None
    if "*" in q or "?" in q:
        rx = re.compile(fnmatch.translate(q))
        return lambda n: rx.match(n) is not None
    palabras = q.split()
    return lambda n: all(w in n for w in palabras)


def buscar_nombre(vol, consulta, borrados=None, stop=None, progress=None, maxres=5000):
    """Recorre el arbol de 'vol' y devuelve ([hallazgos], completo). Cada hallazgo: dict(id, name, dest,
    is_dir, size, mtime, borrado, ruta). 'borrados': True/False fuerza incluirlos o no (None = como esta)."""
    filtro = hacer_filtro(consulta)
    if filtro is None:
        return [], True
    previo = vol.mostrar_borrados
    if borrados is not None and bool(borrados) != bool(previo):
        vol.set_borrados(borrados)
    hits, carpetas, completo = [], 0, True
    skip = getattr(vol, "skip_root", ())
    stack = [(vol.ROOT, "")]
    try:
        while stack and completo:
            if stop is not None and stop.is_set():
                completo = False
                break
            nodo, ruta = stack.pop()
            try:
                ents = vol.children_of(nodo)
            except Exception:
                continue
            sub = []
            for e in ents:
                if nodo == vol.ROOT and e.name.lower() in skip:
                    continue
                full = ruta + "/" + e.name
                if filtro(_norm(e.name)):
                    hits.append(dict(id=e.id, name=e.name, dest=e.dest, is_dir=e.is_dir, size=e.size,
                                     mtime=e.mtime, borrado=bool(e.borrado), ruta=full))
                    if len(hits) >= maxres:
                        completo = False
                        break
                if e.is_dir:
                    sub.append((e.id, full))
            stack.extend(reversed(sub))
            carpetas += 1
            if progress and carpetas % 50 == 0:
                progress(carpetas, len(hits))
    finally:
        if bool(vol.mostrar_borrados) != bool(previo):
            vol.set_borrados(previo)
    if progress:
        progress(carpetas, len(hits))
    return hits, completo


class SearchVolume:
    """Volumen virtual con los resultados de una busqueda por nombre (misma interfaz que los demas).
    Los resultados se muestran planos; una carpeta hallada conserva todo su contenido real."""
    ROOT = 5
    ORPHAN = -1
    NOMBRE = "Busqueda por nombre"
    BASE = 1 << 40

    def __init__(self, real, hits, consulta=""):
        self.real, self.consulta = real, consulta
        self.src = real.src
        self.vol_off = getattr(real, "vol_off", 0)
        self.tparent = {5: None}
        self.mostrar_borrados = real.mostrar_borrados
        self.skip_root = ()
        self.stats = {}
        self._hits = {}
        usados = set()
        self._top = []
        for h in hits:
            dest = h["dest"]
            base, ext = os.path.splitext(dest)
            k = 1
            while dest.lower() in usados:       # mismo nombre en carpetas distintas: se numera
                k += 1
                dest = f"{base} ({k}){ext}"
            usados.add(dest.lower())
            i = self.BASE + h["id"]
            self._hits[i] = h
            self.tparent[i] = 5
            self._top.append(Entrada(i, h["name"], dest, h["is_dir"], h["size"], h["mtime"], h["borrado"]))

    def children_of(self, node):
        if node == 5:
            return [e for e in self._top if self.mostrar_borrados or not e.borrado]
        out = []
        for e in self.real.children_of(node - self.BASE):
            j = self.BASE + e.id
            self.tparent[j] = node
            out.append(e._replace(id=j))
        return out

    def tiene_hijos(self, i):
        return i >= self.BASE and self.real.tiene_hijos(i - self.BASE)

    def info_fila(self, i):
        h = self._hits.get(i)
        return "en " + (os.path.dirname(h["ruta"]) or "/") if h else ""

    def file_size(self, i):
        return self.real.file_size(i - self.BASE)

    def set_borrados(self, v):
        self.mostrar_borrados = bool(v)

    def es_borrado(self, i):
        return self.real.es_borrado(i - self.BASE)

    def info_borrado(self, i):
        t = self.real.info_borrado(i - self.BASE)
        h = self._hits.get(i)
        if h:
            t += "  \u00B7  en " + (os.path.dirname(h["ruta"]) or "/")
        return t

    def extract(self, i, dst, stop=None, force=False, mtime=0):
        return self.real.extract(i - self.BASE, dst, stop, force, mtime)


# --------------------------------------------------------------------------
# Seleccion con casillas (modelo sin interfaz, probado aparte)
# --------------------------------------------------------------------------
class Selection:
    def __init__(self, vol):
        self.vol = vol
        self.explicit = {}

    def _chain(self, n):
        while n is not None:
            yield n
            n = self.vol.tparent.get(n)

    def effective(self, n):
        for x in self._chain(n):
            if x in self.explicit:
                return self.explicit[x]
        return False

    def state(self, n):
        eff = self.effective(n)
        for m, v in self.explicit.items():
            if m != n and v != eff and n in self._chain(m):
                return 2
        return 1 if eff else 0

    def toggle(self, n):
        new = not self.effective(n)
        for m in list(self.explicit):
            if m != n and n in self._chain(m):
                del self.explicit[m]
        self.explicit[n] = new

    def clear(self):
        self.explicit.clear()

    def any(self):
        return any(self.explicit.values())

    def walk(self):
        vol = self.vol
        true_anc = set()
        for m, v in self.explicit.items():
            if v:
                x = m
                while x is not None and x not in true_anc:
                    true_anc.add(x)
                    x = vol.tparent.get(x)
        stack = [(vol.ROOT, self.explicit.get(vol.ROOT, False), ())]
        skip = getattr(vol, "skip_root", ())
        while stack:
            node, eff, rel = stack.pop()
            ents = vol.children_of(node)
            for e in reversed(ents):
                if node == vol.ROOT and e.name.lower() in skip:
                    continue
                ceff = self.explicit.get(e.id, eff)
                crel = rel + (e.dest,)
                if e.is_dir:
                    if ceff:
                        yield ("dir", e.id, crel, e)
                    if ceff or e.id in true_anc:
                        stack.append((e.id, ceff, crel))
                elif ceff:
                    yield ("file", e.id, crel, e)

    def total_size(self, stop=None):
        files = 0
        total = 0
        for kind, rid, rel, e in self.walk():
            if stop is not None and stop.is_set():
                break
            if kind == "file":
                files += 1
                total += self.vol.file_size(rid)
        return files, total


# --------------------------------------------------------------------------
# Copia
# --------------------------------------------------------------------------
def copy_selected(vol, sel, dest, stop, force=False, on_progress=None, total_bytes=0):
    os.makedirs(lp(dest), exist_ok=True)
    logf = open(lp(os.path.join(dest, "recuperacion_log.csv")), "a", newline="", encoding="utf-8")
    w = csv.writer(logf)
    st = dict(ok=0, parcial=0, saltado=0, fallo=0, bytes=0, omitidos=0)
    t_last = 0

    def log(estado, ruta, det=""):
        w.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), estado, ruta, det])
        logf.flush()

    try:
        for kind, rid, rel, e in sel.walk():
            if stop.is_set():
                break
            path = os.path.join(dest, *rel)
            if kind == "dir":
                try:
                    os.makedirs(lp(path), exist_ok=True)
                except OSError as ex:
                    st["fallo"] += 1
                    log("FALLO_DIR", "/".join(rel), repr(ex))
                continue
            ruta = "/" + "/".join(rel)
            try:
                res = vol.extract(rid, path, stop, force, e.mtime)
                estado, nbytes, nbad = res[:3]
                nota = res[3] if len(res) > 3 else ""
            except Exception as ex:
                estado, nbytes, nbad, nota = "ERROR:" + repr(ex), 0, 0, ""

            if estado == "OK":
                st["ok"] += 1
                st["bytes"] += nbytes
            elif estado in ("PARCIAL", "INCOMPLETO"):
                st["parcial"] += 1
                st["bytes"] += nbytes
                log(estado, ruta, nota or f"{nbad} sectores ilegibles (ceros)")
            elif estado == "SALTADO":
                st["saltado"] += 1
                st["bytes"] += nbytes
            elif estado == "DETENIDO":
                break
            elif estado in ("COMPRIMIDO", "CIFRADO", "SIN_DATOS", "SOBRESCRITO"):
                st["omitidos"] += 1
                log(estado, ruta, {"SIN_DATOS": "sin datos que recuperar",
                                   "SOBRESCRITO": "borrado y sobrescrito por otros archivos"}.get(estado, "no soportado"))
            else:
                st["fallo"] += 1
                log("FALLO", ruta, estado)
            now = time.time()
            if on_progress and now - t_last > 0.25:
                t_last = now
                on_progress(dict(st), ruta)
    finally:
        logf.close()
    if on_progress:
        on_progress(dict(st), "")
    return st


# --------------------------------------------------------------------------
# Apertura comun
# --------------------------------------------------------------------------
def index_path(vol):
    base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) \
        else os.path.dirname(os.path.abspath(__file__))
    k = f"{vol.vol_off}_{vol.cs}_{vol.mft_size}"
    return os.path.join(base, "indices", f"indice_mft_{k}.pkl")


def abrir_volumen(source, offset, length=0, mft_cluster=None, usar_cache=True,
                  log=print, progress=None, stop=None):
    src = RawSource(source)
    fs = detectar_fs(src, offset)
    if fs in ("exfat", "fat32", "fat16"):
        try:
            vol = {"exfat": ExFatVolume, "fat32": Fat32Volume, "fat16": Fat16Volume}[fs](src, offset, length, log)
        except Exception:
            src.close()
            raise
        vol.scan(progress, stop)
        return vol
    vol = Volume(src, offset, length, mft_cluster, log)
    ip = index_path(vol)
    if usar_cache and vol.load_index(ip):
        log(f"Indice cargado desde {ip} ({len(vol.rec)} registros). "
            f"Para releer el disco borra ese archivo o desmarca 'usar indice guardado'.")
        return vol
    log(f"Leyendo la MFT completa ({fmt_size(vol.mft_size)})...")
    t = time.time()
    st = vol.scan(progress, stop)
    log(f"MFT leida en {time.time() - t:.0f}s: {st['en_uso']} archivos/carpetas en uso, "
        f"{st['huerfanos']} huerfanos, {st['malos']} registros danados, "
        f"{st['ilegibles']} ilegibles, {st['sectores_ilegibles']} sectores sin leer, "
        f"{st['borrados']} archivos/carpetas borrados con nombre.")
    if usar_cache and vol.save_index(ip):
        log("Indice guardado para abrir mas rapido la proxima vez.")
    return vol


# --------------------------------------------------------------------------
# Linea de comandos
# --------------------------------------------------------------------------
def cli(args):
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    src = RawSource(args.source)
    if args.particiones or args.offset is None:
        ps = leer_particiones(src)
        print("Particiones:")
        for p in ps:
            print(f"  #{p.num}: offset={p.offset} ({p.length / 1e9:.1f} GB) tipo {p.tipo}")
        if args.particiones:
            return 0
        if not ps:
            print("No hay tabla de particiones; usa --offset BYTES.")
            return 1
        big = max(ps, key=lambda p: p.length)
        args.offset, args.length = big.offset, big.length
        print(f"Usando la mas grande: offset {args.offset}")
    src.close()

    def prog(done, total, uso):
        print(f"\r  MFT: {done}/{total} registros ({uso} en uso)", end="", flush=True)

    vol = abrir_volumen(args.source, args.offset, args.length or 0, args.mft_cluster,
                        not args.sin_cache, log=print, progress=prog)
    print()
    if getattr(args, "borrados", False):
        vol.set_borrados(True)
    if args.ls is not None:
        node = vol.find(args.ls)
        if node is None:
            print("No existe esa ruta.")
            return 1
        for e in vol.children_of(node):
            print(f"{'<DIR>' if e.is_dir else fmt_size(vol.file_size(e.id) if not e.is_dir else 0):>10}  {e.name}")
    if args.copiar is not None:
        if not args.dest:
            print("Falta --dest")
            return 1
        node = vol.find(args.copiar)
        if node is None:
            print("No existe esa ruta.")
            return 1
        sel = Selection(vol)
        sel.explicit[node] = True
        stop = threading.Event()
        files, total = sel.total_size()
        print(f"Copiando {files} archivos, {fmt_size(total)} ...")
        st = copy_selected(vol, sel, args.dest, stop, args.forzar,
                           lambda s, r: print(f"\r  OK {s['ok']} parciales {s['parcial']} fallos {s['fallo']} "
                                              f"{fmt_size(s['bytes'])}  {r[-50:]:<50}", end="", flush=True), total)
        print(f"\nListo: {st}")
    return 0


# --------------------------------------------------------------------------
# Discos y unidades (Windows, solo ctypes: no hace falta instalar nada)
# --------------------------------------------------------------------------
BUS = {1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "1394", 6: "FC", 7: "USB", 8: "RAID", 9: "iSCSI",
       10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 14: "Virtual", 15: "Virtual", 16: "Spaces", 17: "NVMe"}
SKIP_ROOT = ("$recycle.bin", "system volume information")
_K = None


def es_admin():
    if os.name != "nt":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relanzar_como_admin(extra=()):
    """Pide permisos de administrador (aviso de Windows) y vuelve a lanzar el programa."""
    import ctypes
    import subprocess
    if getattr(sys, "frozen", False):          # ejecutable (.exe)
        params = subprocess.list2cmdline(list(sys.argv[1:]) + list(extra))
    else:                                       # script .py
        params = subprocess.list2cmdline([os.path.abspath(sys.argv[0])] + list(sys.argv[1:]) + list(extra))
    r = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, os.getcwd(), 1)
    return r > 32


def _k32():
    global _K
    if _K is not None:
        return _K
    import ctypes
    from ctypes import wintypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.restype = ctypes.c_void_p
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                              wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    k.DeviceIoControl.restype = wintypes.BOOL
    k.DeviceIoControl.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                  ctypes.c_void_p]
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    k.GetLogicalDrives.restype = wintypes.DWORD
    k.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    k.GetDriveTypeW.restype = wintypes.UINT
    k.GetVolumeInformationW.restype = wintypes.BOOL
    k.GetVolumeInformationW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
                                        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                        wintypes.LPWSTR, wintypes.DWORD]
    k.SetErrorMode.argtypes = [wintypes.UINT]
    k.SetErrorMode(1)   # no mostrar cuadros de "inserte un disco"
    _K = k
    return k


def _win_open(path):
    """Abre un dispositivo SIN pedir acceso de lectura (alcanza para consultar tamano y datos)."""
    import ctypes
    k = _k32()
    h = k.CreateFileW(path, 0, 3, None, 3, 0, None)
    if h in (None, 0, ctypes.c_void_p(-1).value):
        return None
    return h


def _ioctl(h, code, inbuf=b"", outsize=4096):
    import ctypes
    from ctypes import wintypes
    k = _k32()
    out = ctypes.create_string_buffer(outsize)
    ret = wintypes.DWORD(0)
    inb = ctypes.create_string_buffer(inbuf, len(inbuf)) if inbuf else None
    ok = k.DeviceIoControl(h, code, inb, len(inbuf), out, outsize, ctypes.byref(ret), None)
    return out.raw[:ret.value] if ok else None


def _extents_de_letra(letra):
    """(numero_de_disco, offset, largo) de una unidad con letra, o None."""
    h = _win_open("\\\\.\\" + letra + ":")
    if h is None:
        return None
    try:
        ext = _ioctl(h, 0x00560000, outsize=256)     # IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
    finally:
        _k32().CloseHandle(h)
    if not ext or len(ext) < 32 or struct.unpack_from("<I", ext, 0)[0] < 1:
        return None
    disco = struct.unpack_from("<I", ext, 8)[0]
    off, ln = struct.unpack_from("<qq", ext, 16)
    return disco, off, ln


def disco_de_ruta(path):
    """Numero de disco fisico donde esta una carpeta (por su letra de unidad), o None."""
    if os.name != "nt":
        return None
    drive = os.path.splitdrive(os.path.abspath(path))[0]
    if len(drive) == 2 and drive[1] == ":":
        r = _extents_de_letra(drive[0].upper())
        return r[0] if r else None
    return None


def listar_discos_fisicos():
    if os.name != "nt":
        return []
    out = []
    for n in range(32):
        path = "\\\\.\\PhysicalDrive%d" % n
        h = _win_open(path)
        if h is None:
            continue
        try:
            geo = _ioctl(h, 0x000700A0, outsize=256)           # IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
            size = struct.unpack_from("<q", geo, 24)[0] if geo and len(geo) >= 32 else 0
            q = struct.pack("<IIB3x", 0, 0, 0)                 # StorageDeviceProperty
            d = _ioctl(h, 0x002D1400, q, 1024)                 # IOCTL_STORAGE_QUERY_PROPERTY
        finally:
            _k32().CloseHandle(h)
        model, bus, removable = "", 0, False
        if d and len(d) >= 32:
            removable = bool(d[10])
            vo, po = struct.unpack_from("<II", d, 12)
            bus = struct.unpack_from("<I", d, 28)[0]

            def cstr(o):
                if not o or o >= len(d):
                    return ""
                e = d.find(b"\x00", o)
                return d[o: len(d) if e < 0 else e].decode("ascii", "replace").strip()
            model = (cstr(vo) + " " + cstr(po)).strip()
        out.append(dict(num=n, path=path, size=size, model=model or "Disco", bus=BUS.get(bus, "?"),
                        removable=removable, es_sistema=False, parts=[], error=""))
    return out


def letras_volumenes():
    """{letra: dict(disco, offset, length, etiqueta, fs)} de las unidades con letra."""
    import ctypes
    if os.name != "nt":
        return {}
    k = _k32()
    mask = k.GetLogicalDrives()
    res = {}
    for i in range(26):
        if not mask & (1 << i):
            continue
        L = chr(65 + i)
        if k.GetDriveTypeW(L + ":\\") not in (2, 3):     # solo extraibles y fijos
            continue
        e = _extents_de_letra(L)
        if e is None:
            continue
        vol = ctypes.create_unicode_buffer(261)
        fs = ctypes.create_unicode_buffer(261)
        ok = k.GetVolumeInformationW(L + ":\\", vol, 261, None, None, None, fs, 261)
        res[L] = dict(disco=e[0], offset=e[1], length=e[2],
                      etiqueta=vol.value if ok else "", fs=fs.value if ok else "")
    return res


def _fs_de_arranque(b):
    if b[3:11] == b"NTFS    ":
        return "NTFS"
    if b[3:11] == b"EXFAT   ":
        return "exFAT"
    if b[82:90] == b"FAT32   ":
        return "FAT32"
    g = Fat16Volume.parse_boot(b)
    if g:
        return g["tipo"]
    return ""


def particiones_con_fs(src, size):
    """Particiones del origen + sistema de archivos detectado en el sector de arranque."""
    out = []
    for p in leer_particiones(src):
        fs = _fs_de_arranque(src.read(p.offset, 512))
        if not fs and p.length >= 1024 * 1024:
            if src.read(p.offset + p.length - 512, 512)[3:11] == b"NTFS    ":
                fs = "NTFS (sector de arranque dañado)"
            elif src.read(p.offset + 6 * 512, 512)[82:90] == b"FAT32   ":
                fs = "FAT32 (sector de arranque dañado)"
            elif any(src.read(p.offset + (12 << sh), 512)[3:11] == b"EXFAT   " for sh in (9, 10, 11, 12)):
                fs = "exFAT (sector de arranque dañado)"
        out.append(dict(num=p.num, offset=p.offset, length=p.length, tipo=p.tipo, fs=fs, letra="", etiqueta=""))
    if not out and _fs_de_arranque(src.read(0, 512)):
        out.append(dict(num=0, offset=0, length=size, tipo="sin tabla",
                        fs=_fs_de_arranque(src.read(0, 512)), letra="", etiqueta=""))
    return out


def info_imagen(path):
    s = RawSource(path)
    try:
        size = os.path.getsize(path)
        parts = particiones_con_fs(s, size)
    finally:
        s.close()
    return dict(num=None, path=path, size=size, model="Imagen: " + os.path.basename(path), bus="archivo",
                removable=False, es_sistema=False, parts=parts, error="")


def listar_todo(admin=True):
    """Discos fisicos con sus particiones y letras de unidad (Windows).
    Sin permisos de administrador solo se ven las unidades con letra."""
    discos = listar_discos_fisicos()
    letras = letras_volumenes()
    sysl = os.environ.get("SystemDrive", "C:")[:1].upper()
    for d in discos:
        d["es_sistema"] = any(L == sysl and v["disco"] == d["num"] for L, v in letras.items())
        if admin:
            try:
                s = RawSource(d["path"])
                try:
                    d["parts"] = particiones_con_fs(s, d["size"])
                finally:
                    s.close()
            except OSError as e:
                d["error"] = str(e)
        for L, v in letras.items():
            if v["disco"] != d["num"]:
                continue
            for p in d["parts"]:
                if p["offset"] == v["offset"]:
                    p["letra"], p["etiqueta"] = L, v["etiqueta"]
                    if not p["fs"] and v["fs"]:
                        p["fs"] = v["fs"]
                    break
            else:
                d["parts"].append(dict(num=0, offset=v["offset"], length=v["length"], tipo="volumen",
                                       fs=v["fs"], letra=L, etiqueta=v["etiqueta"]))
    return discos




# --------------------------------------------------------------------------
# Interfaz grafica: UN solo arbol  Discos > Particiones > Carpetas y archivos
# --------------------------------------------------------------------------
APP_TITLE = "Reflota"

PAL = dict(bg="#F3F5F9", card="#FFFFFF", line="#E1E6EF", ink="#18212F", muted="#6B7788", faint="#A3ADBB",
           navy="#0D1828", acc="#1E6FD9", acc_d="#1757AF", btn="#EAEFF7", selbg="#D8E7FC", diskbg="#EDF2FA",
           ok="#0E5FC9", half="#8A5F00", bad="#C0392B", dele="#B5483A", warn_bg="#FFF4D6", warn_fg="#6B4E00")

EXT_ICON = {}
for _ic, _exts in (("\U0001F5BC", ".jpg .jpeg .png .gif .bmp .webp .tif .tiff .heic .raw .cr2 .nef"),
                   ("\U0001F3B5", ".mp3 .wav .flac .m4a .ogg .aac .wma"),
                   ("\U0001F3AC", ".mp4 .mkv .avi .mov .wmv .flv .webm .mpg .mpeg .3gp"),
                   ("\U0001F4D5", ".pdf"),
                   ("\U0001F4CA", ".xls .xlsx .csv .ods"),
                   ("\U0001F4DD", ".doc .docx .odt .rtf .txt .md"),
                   ("\U0001F4E6", ".zip .rar .7z .tar .gz .iso"),
                   ("\u2699", ".exe .dll .msi .sys .bat"),
                   ("\U0001F4DC", ".py .js .html .css .json .xml .c .cpp .java .cs .ps1")):
    for _e in _exts.split():
        EXT_ICON[_e] = _ic


def _recurso(nombre):
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, nombre)


def _dibujar_logo(cv, s):
    """Logo de Reflota (flecha que sube sobre dos olas) dibujado con formas, sin archivos."""
    a = PAL["acc"]
    r, m = s * 0.22, s * 0.04
    x0, y0, x1, y1 = m, m, s - m, s - m
    for ax, ay in ((x0, y0), (x1 - 2 * r, y0), (x0, y1 - 2 * r), (x1 - 2 * r, y1 - 2 * r)):
        cv.create_oval(ax, ay, ax + 2 * r, ay + 2 * r, fill=a, outline=a)
    cv.create_rectangle(x0 + r, y0, x1 - r, y1, fill=a, outline=a)
    cv.create_rectangle(x0, y0 + r, x1, y1 - r, fill=a, outline=a)
    cv.create_polygon(s * .5, s * .16, s * .2, s * .50, s * .8, s * .50, fill="#FFFFFF", outline="#FFFFFF")
    cv.create_rectangle(s * .41, s * .48, s * .59, s * .74, fill="#FFFFFF", outline="#FFFFFF")
    for base in (.82, .91):
        pts = []
        for i in range(25):
            u = .18 + .64 * i / 24
            pts += [s * u, s * (base + .022 * math.sin(u * 2 * math.pi * 3.2))]
        cv.create_line(*pts, fill="#FFFFFF", width=max(2, s * .04), smooth=True, capstyle="round")


def run_gui(abrir=None):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    MARCA = {0: "\u2610", 1: "\u2611", 2: "\u25EA"}
    P = PAL

    if os.name == "nt":                      # nitidez en pantallas de alta resolucion
        try:
            import ctypes
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(APP_TITLE)
            self.k = max(1.0, self.winfo_fpixels("1i") / 96.0)
            w = min(int(1120 * self.k), self.winfo_screenwidth() - 60)
            h = min(int(860 * self.k), self.winfo_screenheight() - 90)
            self.geometry(f"{w}x{h}")
            self.minsize(self.sc(1040), self.sc(640))
            self._icono()
            self.admin = es_admin()
            self.abrir_arg = abrir
            self.items = {}          # iid de disco/particion -> dict(kind, disk, diskiid, part, ok)
            self.rowkind = {}        # iid de carpeta/archivo -> "dir" | "file"
            self.rowname = {}        # iid -> nombre corto (para la ruta)
            self.imagenes = []
            self.vols = {}           # pid -> Volume ya leido
            self.sels = {}           # pid -> Selection
            self.loaded = set()      # iids cuyos hijos ya se dibujaron
            self.tick_pending = set()  # particiones tildadas que todavia se estan leyendo
            self.load_q = []
            self.loading = None
            self.mft_override = {}
            self.copying = False
            self.stop = threading.Event()
            self.calc_stop = None
            self.calc_gen = 0
            self.calc_busy = False
            self.total_est = 0
            self.files_est = 0
            self.last_dest = ""
            self.tarea = None          # 'contenido' | 'particiones' | 'imagen' mientras corre
            self.carve_srcs = []       # origenes abiertos de los resultados por contenido
            self.parts_extra = {}      # particiones encontradas a mano (ruta del disco -> lista)
            self.q = queue.Queue()
            self.report_callback_exception = self._err
            self._estilo()
            self._ui()
            self.after(150, self._poll)
            self.after(200, self.refrescar)

        def sc(self, n):
            return int(n * self.k)

        def _icono(self):
            try:
                ico = _recurso("icon.ico")
                if os.path.exists(ico):
                    self.iconbitmap(ico)
                    return
            except Exception:
                pass
            try:   # sin icono propio: icono transparente en vez de la pluma de Tk
                self.iconphoto(True, tk.PhotoImage(width=16, height=16))
            except Exception:
                pass

        # ----------------------------------------------------------- estilo
        def _estilo(self):
            sc = self.sc
            st = ttk.Style(self)
            try:
                st.theme_use("clam")
            except tk.TclError:
                pass
            self.configure(bg=P["bg"])
            base = ("Segoe UI", 10)
            st.configure(".", font=base, background=P["bg"], foreground=P["ink"])
            st.configure("TFrame", background=P["bg"])
            st.configure("TLabel", background=P["bg"], foreground=P["ink"])
            st.configure("TButton", background=P["btn"], foreground=P["ink"], bordercolor=P["line"],
                         lightcolor=P["btn"], darkcolor=P["btn"], focuscolor=P["btn"],
                         padding=(sc(14), sc(7)), relief="flat", borderwidth=1)
            st.map("TButton", background=[("disabled", "#F1F4F9"), ("pressed", "#D5DFEE"), ("active", "#E1E9F5")],
                   foreground=[("disabled", "#A8B2C0")], bordercolor=[("active", "#C3D0E4")])
            st.configure("Accent.TButton", background=P["acc"], foreground="#FFFFFF", bordercolor=P["acc"],
                         lightcolor=P["acc"], darkcolor=P["acc"], focuscolor=P["acc"],
                         padding=(sc(24), sc(9)), font=("Segoe UI Semibold", 11))
            st.map("Accent.TButton", background=[("disabled", "#B9C9E2"), ("pressed", "#134A99"), ("active", P["acc_d"])],
                   foreground=[("disabled", "#FFFFFF")], bordercolor=[("disabled", "#B9C9E2"), ("active", P["acc_d"])])
            st.configure("TMenubutton", background=P["btn"], foreground=P["ink"], bordercolor=P["line"],
                         arrowcolor=P["ink"], padding=(sc(14), sc(7)), relief="flat")
            st.map("TMenubutton", background=[("disabled", "#F1F4F9"), ("active", "#E1E9F5")],
                   foreground=[("disabled", "#A8B2C0")])
            st.configure("Bar.TRadiobutton", background=P["bg"], foreground=P["ink"], indicatorbackground="#FFFFFF",
                         indicatorforeground=P["acc"])
            st.map("Bar.TRadiobutton", background=[("active", P["bg"])], foreground=[("disabled", "#A8B2C0")],
                   indicatorforeground=[("selected", P["acc"])])
            for nombre, fondo, letra in (("Card.TCheckbutton", P["card"], P["ink"]),
                                         ("Bar.TCheckbutton", P["bg"], P["muted"])):
                st.configure(nombre, background=fondo, foreground=letra, indicatorbackground="#FFFFFF",
                             indicatorforeground="#FFFFFF", bordercolor="#B9C4D6", focuscolor=fondo)
                st.map(nombre, background=[("active", fondo)],
                       indicatorbackground=[("selected", P["acc"]), ("!selected", "#FFFFFF")],
                       indicatorforeground=[("selected", "#FFFFFF")])
            st.configure("TEntry", fieldbackground="#FFFFFF", bordercolor=P["line"], lightcolor=P["line"],
                         darkcolor=P["line"], padding=sc(7))
            st.configure("Treeview", background=P["card"], fieldbackground=P["card"], foreground=P["ink"],
                         rowheight=sc(30), borderwidth=0, relief="flat", font=base)
            try:
                st.configure("Treeview", indent=sc(20))
            except tk.TclError:
                pass
            st.configure("Treeview.Heading", background="#EEF2F8", foreground=P["muted"], relief="flat",
                         borderwidth=0, padding=(sc(10), sc(9)), font=("Segoe UI Semibold", 9))
            st.map("Treeview.Heading", background=[("active", "#E6EBF4")])
            try:   # arregla el color de filas por etiqueta en Tk 8.6.9 y deja la seleccion visible
                keep = [e for e in st.map("Treeview", query_opt="background") if e[:2] != ("!disabled", "!selected")]
                keepf = [e for e in st.map("Treeview", query_opt="foreground") if e[:2] != ("!disabled", "!selected")]
                st.map("Treeview", background=[("selected", P["selbg"])] + keep,
                       foreground=[("selected", P["ink"])] + keepf)
            except tk.TclError:
                st.map("Treeview", background=[("selected", P["selbg"])], foreground=[("selected", P["ink"])])
            try:
                st.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])      # sin borde interior
                st.layout("Slim.Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {
                    "sticky": "ns", "children": [("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
                st.configure("Slim.Vertical.TScrollbar", background="#C9D3E2", troughcolor=P["card"],
                             bordercolor=P["card"], lightcolor="#C9D3E2", darkcolor="#C9D3E2", width=sc(10), gripcount=0)
                st.map("Slim.Vertical.TScrollbar", background=[("active", "#A9B8CF")])
            except tk.TclError:
                pass
            st.configure("Bar.Horizontal.TProgressbar", troughcolor="#E1E7F0", background=P["acc"],
                         bordercolor="#E1E7F0", lightcolor=P["acc"], darkcolor=P["acc"], thickness=sc(8))

        def _tags(self):
            """Una etiqueta por tipo de fila y estado: 0 sin tildar, 1 tildado, 2 parcial."""
            fg_state = {1: P["ok"], 2: P["half"]}
            base = {"disk": (P["ink"], ("Segoe UI Semibold", 10), P["diskbg"]),
                    "part": (P["ink"], None, None),
                    "bad": (P["faint"], None, None),
                    "dir": (P["ink"], None, None),
                    "file": ("#3E4A5C", None, None),
                    "ddir": (P["dele"], None, None),
                    "dfile": (P["dele"], None, None)}
            for b, (fg, font, bg) in base.items():
                for s in (0, 1, 2):
                    opts = dict(foreground=fg_state.get(s, fg))
                    if font:
                        opts["font"] = font
                    if bg:
                        opts["background"] = bg
                    self.tree.tag_configure(f"{b}{s}", **opts)

        # ----------------------------------------------------------- UI
        def _ui(self):
            sc = self.sc
            # encabezado
            hd = tk.Frame(self, bg=P["navy"])
            hd.pack(fill="x")
            logo = tk.Canvas(hd, width=sc(42), height=sc(42), bg=P["navy"], highlightthickness=0)
            logo.pack(side="left", padx=(sc(20), sc(12)), pady=sc(13))
            _dibujar_logo(logo, sc(42))
            tk.Label(hd, text="Reflota", bg=P["navy"], fg="#FFFFFF", font=("Segoe UI Semibold", 20)).pack(side="left")
            tk.Label(hd, text="\u25CF  Solo lectura", bg=P["navy"], fg="#7FD8A6",
                     font=("Segoe UI", 9)).pack(side="right", padx=sc(22))
            tk.Frame(self, bg=P["acc"], height=2).pack(fill="x")

            # aviso de permisos (solo si no es administrador)
            self.ban = tk.Frame(self, bg=P["warn_bg"])
            tk.Label(self.ban, text="Sin permisos de administrador: solo se ven las unidades con letra. "
                                    "Para ver todos los discos (incluso dañados) Windows pide permiso.",
                     bg=P["warn_bg"], fg=P["warn_fg"], font=("Segoe UI", 9), anchor="w", justify="left",
                     wraplength=sc(820)).pack(side="left", padx=sc(20), pady=sc(8))
            ttk.Button(self.ban, text="Ver todos los discos",
                       command=lambda: self._pedir_admin(None)).pack(side="right", padx=sc(20))
            if os.name == "nt" and not self.admin:
                self.ban.pack(fill="x")

            body = tk.Frame(self, bg=P["bg"])
            body.pack(fill="both", expand=True, padx=sc(20), pady=(sc(16), sc(4)))
            top = tk.Frame(body, bg=P["bg"])
            top.pack(fill="x", pady=(0, sc(10)))
            tk.Label(top, text="¿Qué querés recuperar?", bg=P["bg"], fg=P["ink"],
                     font=("Segoe UI Semibold", 14)).pack(side="left")
            self.adv = tk.BooleanVar(value=False)
            ttk.Checkbutton(top, text="Avanzado", variable=self.adv, command=self._toggle_adv,
                            style="Bar.TCheckbutton").pack(side="right", padx=(sc(10), 0))
            self.show_del = tk.BooleanVar(value=False)
            self.chk_del = ttk.Checkbutton(top, text="Incluir archivos borrados", variable=self.show_del,
                                           command=self._toggle_borrados, style="Bar.TCheckbutton")
            self.chk_del.pack(side="right", padx=(sc(10), 0))
            self.btn_clear = ttk.Button(top, text="Destildar todo", command=self.destildar)
            self.btn_clear.pack(side="right", padx=(sc(6), 0))
            self.btn_tools = ttk.Menubutton(top, text="Herramientas")
            mn = tk.Menu(self.btn_tools, tearoff=0, bg="#FFFFFF", fg=P["ink"], activebackground=P["selbg"],
                         activeforeground=P["ink"], font=("Segoe UI", 10), bd=0, relief="flat")
            mn.add_command(label="Buscar archivos por contenido\u2026", command=self.dlg_contenido)
            mn.add_command(label="Buscar particiones perdidas\u2026", command=self.dlg_particiones)
            mn.add_command(label="Crear imagen del disco (copia segura)\u2026", command=self.dlg_imagen)
            self.btn_tools["menu"] = mn
            self.btn_tools.pack(side="right", padx=(sc(6), 0))
            self.btn_img = ttk.Button(top, text="Abrir imagen\u2026", command=self.elegir_img)
            self.btn_img.pack(side="right", padx=(sc(6), 0))
            self.btn_ref = ttk.Button(top, text="\u21BB  Actualizar", command=self.refrescar)
            self.btn_ref.pack(side="right")

            bs = tk.Frame(body, bg=P["bg"])
            bs.pack(fill="x", pady=(0, sc(8)))
            tk.Label(bs, text="Buscar por nombre", bg=P["bg"], fg=P["muted"],
                     font=("Segoe UI", 9)).pack(side="left", padx=(0, sc(8)))
            self.q_name = tk.StringVar()
            self.ent_name = ttk.Entry(bs, textvariable=self.q_name)
            self.ent_name.pack(side="left", fill="x", expand=True)
            self.ent_name.bind("<Return>", lambda e: self.buscar_por_nombre())
            self.btn_find = ttk.Button(bs, text="Buscar", command=self.buscar_por_nombre)
            self.btn_find.pack(side="left", padx=(sc(8), 0))
            tk.Label(bs, text="ej.: factura  \u00B7  *.pdf  \u00B7  foto_??.jpg", bg=P["bg"], fg=P["muted"],
                     font=("Segoe UI", 9)).pack(side="left", padx=(sc(10), 0))

            card = tk.Frame(body, bg=P["card"], highlightbackground=P["line"], highlightcolor=P["line"],
                            highlightthickness=1)
            card.pack(fill="both", expand=True)
            self.tree = ttk.Treeview(card, columns=("sel", "size", "info"), selectmode="browse", height=3)
            self.tree.heading("#0", text="Nombre", anchor="w")
            self.tree.heading("sel", text="Recuperar")
            self.tree.heading("size", text="Tamaño", anchor="e")
            self.tree.heading("info", text="Detalle / modificado", anchor="w")
            self.tree.column("#0", width=sc(540))
            self.tree.column("sel", width=sc(86), anchor="center", stretch=False)
            self.tree.column("size", width=sc(100), anchor="e", stretch=False)
            self.tree.column("info", width=sc(330))
            sb = ttk.Scrollbar(card, orient="vertical", command=self.tree.yview, style="Slim.Vertical.TScrollbar")
            self.tree.configure(yscrollcommand=sb.set)
            self.tree.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            self._tags()
            self.tree.bind("<<TreeviewOpen>>", self.on_open)
            self.tree.bind("<<TreeviewSelect>>", self._on_select)
            self.tree.bind("<Button-1>", self.on_click)
            self.tree.bind("<space>", lambda e: self.toggle(self.tree.focus()))
            self.lbl_ruta = tk.Label(body, text=" ", bg=P["bg"], fg=P["muted"], font=("Segoe UI", 9), anchor="w")
            self.lbl_ruta.pack(fill="x", pady=(sc(6), 0))

            # opciones avanzadas (ocultas)
            self.fadv = tk.Frame(self, bg=P["card"], highlightbackground=P["line"], highlightcolor=P["line"],
                                 highlightthickness=1)
            ra = tk.Frame(self.fadv, bg=P["card"])
            ra.pack(fill="x", padx=sc(14), pady=sc(10))
            tk.Label(ra, text="Elegí la fila del disco.  Offset del volumen NTFS (bytes):", bg=P["card"],
                     fg=P["ink"]).pack(side="left")
            self.offm = tk.StringVar()
            ttk.Entry(ra, textvariable=self.offm, width=16).pack(side="left", padx=(sc(8), sc(14)))
            tk.Label(ra, text="Cluster de la MFT (opcional):", bg=P["card"], fg=P["ink"]).pack(side="left")
            self.mftc = tk.StringVar()
            ttk.Entry(ra, textvariable=self.mftc, width=12).pack(side="left", padx=(sc(8), sc(14)))
            ttk.Button(ra, text="Leer ese volumen", command=self.abrir_manual).pack(side="left")

            # destino y recuperar
            self.fd = tk.Frame(self, bg=P["card"], highlightbackground=P["line"], highlightcolor=P["line"],
                               highlightthickness=1)
            self.fd.pack(fill="x", padx=sc(20), pady=(sc(8), sc(8)))
            inner = tk.Frame(self.fd, bg=P["card"])
            inner.pack(fill="x", padx=sc(16), pady=sc(14))
            r1 = tk.Frame(inner, bg=P["card"])
            r1.pack(fill="x")
            tk.Label(r1, text="Copiar a", bg=P["card"], fg=P["ink"],
                     font=("Segoe UI Semibold", 10)).pack(side="left", padx=(0, sc(12)))
            self.dest = tk.StringVar()
            self.dest.trace_add("write", lambda *a: self._update_summary())
            ttk.Entry(r1, textvariable=self.dest).pack(side="left", fill="x", expand=True)
            ttk.Button(r1, text="Elegir carpeta\u2026", command=self.elegir_dest).pack(side="left", padx=(sc(8), 0))
            tk.Label(inner, text="Elegí una carpeta en OTRO disco, nunca en el que estás recuperando.",
                     bg=P["card"], fg=P["muted"], font=("Segoe UI", 9)).pack(anchor="w", pady=(sc(5), 0))
            r2 = tk.Frame(inner, bg=P["card"])
            r2.pack(fill="x", pady=(sc(8), 0))
            self.chk_force = tk.BooleanVar()
            ttk.Checkbutton(r2, text="Recopiar aunque ya exista", variable=self.chk_force,
                            style="Card.TCheckbutton").pack(side="left")
            self.skip_sys = tk.BooleanVar(value=True)
            ttk.Checkbutton(r2, text="Omitir papelera y System Volume Information", variable=self.skip_sys,
                            command=self._after_change, style="Card.TCheckbutton").pack(side="left", padx=sc(18))
            r3 = tk.Frame(inner, bg=P["card"])
            r3.pack(fill="x", pady=(sc(12), 0))
            self.btn_go = ttk.Button(r3, text="\u25B6  RECUPERAR", command=self.recuperar, state="disabled",
                                     style="Accent.TButton")
            self.btn_go.pack(side="right")
            self.btn_stop = ttk.Button(r3, text="\u25A0  Parar", command=self.parar, state="disabled")
            self.btn_stop.pack(side="right", padx=(0, sc(10)))
            self.lbl_sel = tk.Label(r3, text="", bg=P["card"], fg=P["ink"], font=("Segoe UI Semibold", 11), anchor="w")
            self.lbl_sel.pack(side="left", fill="x", expand=True)

            self.pb = ttk.Progressbar(self, mode="determinate", style="Bar.Horizontal.TProgressbar")
            self.pb.pack(fill="x", padx=sc(20))
            self.lbl = tk.Label(self, text="Listo.", bg=P["bg"], fg=P["muted"], font=("Segoe UI", 9), anchor="w")
            self.lbl.pack(fill="x", padx=sc(20), pady=(sc(4), 0))
            self.txt = tk.Text(self, height=3, state="disabled", bg="#F9FAFD", fg=P["muted"], relief="flat",
                               highlightbackground=P["line"], highlightcolor=P["line"], highlightthickness=1,
                               font=("Consolas", 9), padx=sc(8), pady=sc(6))
            self.txt.pack(fill="x", padx=sc(20), pady=(sc(6), sc(14)))
            self._update_summary()

        def _toggle_borrados(self):
            """Muestra/oculta los archivos borrados en todas las particiones ya leidas."""
            if self.copying or self.loading is not None:
                self.show_del.set(not self.show_del.get())
                return
            val = self.show_del.get()
            for pid, vol in self.vols.items():
                vol.set_borrados(val)
                if not val:                         # lo que ya no se ve, sale de la seleccion
                    sel = self.sels[pid]
                    for k in [k for k in sel.explicit if vol.es_borrado(k)]:
                        del sel.explicit[k]
                for iid in [i for i in self.loaded if i == pid or i.startswith(pid + ":")]:
                    self.loaded.discard(iid)
                self._poblar_particion(pid)
            if val:
                self.lbl.configure(text="Los archivos borrados se ven en rojo; el % dice cuánto de su contenido "
                                        "sigue sin pisar.")
            self._after_change()

        def _toggle_adv(self):
            if self.adv.get():
                self.fadv.pack(fill="x", padx=self.sc(20), pady=(self.sc(6), 0), before=self.fd)
            else:
                self.fadv.pack_forget()

        def say(self, s):
            self.txt.configure(state="normal")
            self.txt.insert("end", s + "\n")
            self.txt.see("end")
            self.txt.configure(state="disabled")

        def _err(self, exc, val, tb):
            import traceback
            self.say("ERROR: " + "".join(traceback.format_exception(exc, val, tb))[-1200:])

        def _on_select(self, _e=None):
            sel = self.tree.selection()
            iid = sel[0] if sel else None
            partes = []
            while iid:
                n = self.rowname.get(iid)
                if n:
                    partes.append(n)
                iid = self.tree.parent(iid)
            self.lbl_ruta.configure(text="   \u203A   ".join(reversed(partes)) if partes else " ")

        # ------------------------------------------------- estado / resumen
        def _hay_tilde(self):
            return bool(self.tick_pending) or any(s.any() for s in self.sels.values())

        def _controls(self):
            ocupado = self.loading is not None or bool(self.load_q) or self.tarea is not None
            puede = self._hay_tilde() and not (self.copying or ocupado or self.calc_busy)
            self.btn_go.configure(state="normal" if puede else "disabled")
            self.btn_stop.configure(state="normal" if (self.copying or ocupado) else "disabled")
            for b in (self.btn_ref, self.btn_img, self.btn_clear, self.chk_del, self.btn_tools, self.btn_find):
                b.configure(state="disabled" if (self.copying or ocupado) else "normal")

        def _libre_destino(self):
            dest = self.dest.get().strip()
            if not dest:
                return None
            d = os.path.abspath(dest)
            while not os.path.exists(d):
                nd = os.path.dirname(d)
                if nd == d:
                    return None
                d = nd
            try:
                return shutil.disk_usage(d).free
            except OSError:
                return None

        def _update_summary(self):
            color = P["ink"]
            if self.tick_pending:
                txt = "Leyendo el disco para calcular el tamaño\u2026"
                color = P["muted"]
            elif self.calc_busy:
                txt = "Calculando el tamaño\u2026"
                color = P["muted"]
            elif not self._hay_tilde():
                txt = "Tildá un disco, una partición, carpetas o archivos."
                color = P["muted"]
            else:
                txt = f"Seleccionado: {self.files_est} archivos \u00B7 {fmt_size(self.total_est)}"
                libre = self._libre_destino()
                if libre is not None:
                    txt += f"   \u00B7   libre en el destino: {fmt_size(libre)}"
                    if self.total_est > libre:
                        txt += "   \u26A0 NO ENTRA"
                        color = P["bad"]
            self.lbl_sel.configure(text=txt, fg=color)

        def _apply_opts(self):
            for v in self.vols.values():
                v.skip_root = SKIP_ROOT if self.skip_sys.get() else ()

        def _after_change(self):
            self.refresh_marks()
            self._recalc()
            self._controls()

        def _recalc(self):
            """Recalcula el tamaño de lo tildado en segundo plano (cada vez que se tilda algo)."""
            if self.calc_stop is not None:
                self.calc_stop.set()
            self.calc_stop = None
            self._apply_opts()
            snaps = []
            for sel in self.sels.values():
                if sel.any():
                    s2 = Selection(sel.vol)
                    s2.explicit = dict(sel.explicit)     # copia: el hilo no toca la seleccion viva
                    snaps.append(s2)
            if not snaps:
                self.total_est = self.files_est = 0
                self.calc_busy = False
                self._update_summary()
                return
            ev = threading.Event()
            self.calc_stop = ev
            self.calc_gen += 1
            self.calc_busy = True
            self._update_summary()
            threading.Thread(target=self._calc_worker, args=(self.calc_gen, ev, snaps), daemon=True).start()

        def _calc_worker(self, gen, ev, snaps):
            try:
                files = total = 0
                for s in snaps:
                    f, t = s.total_size(ev)
                    if ev.is_set():
                        return
                    files += f
                    total += t
                self.q.put(("calc", (gen, files, total)))
            except Exception as e:
                self.q.put(("msg", f"Error calculando: {e!r}"))
                self.q.put(("calc", (gen, 0, 0)))

        # ------------------------------------------------- lista de discos
        def refrescar(self):
            if self.copying or self.loading is not None or self.tarea is not None:
                return
            self.btn_ref.configure(state="disabled")
            self.lbl.configure(text="Buscando discos y unidades\u2026")
            threading.Thread(target=self._lista_worker, args=(self.admin,), daemon=True).start()

        def _lista_worker(self, admin):
            try:
                self.q.put(("discos", listar_todo(admin)))
            except Exception as e:
                self.q.put(("msg", f"No pude listar los discos: {e!r}"))
                self.q.put(("discos", []))

        def elegir_img(self):
            p = filedialog.askopenfilename(title="Imagen de disco")
            if not p:
                return
            try:
                self.imagenes.append(info_imagen(p))
            except Exception as e:
                messagebox.showerror("Error", f"No pude abrir la imagen:\n{e}")
                return
            self.refrescar()

        def _fill_discos(self, discos):
            self.tree.delete(*self.tree.get_children())
            for c in (self.items, self.vols, self.sels, self.mft_override, self.rowkind, self.rowname):
                c.clear()
            for sc_ in self.carve_srcs:
                try:
                    sc_.close()
                except Exception:
                    pass
            self.carve_srcs.clear()
            self.loaded.clear()
            self.tick_pending.clear()
            self.load_q.clear()
            self.total_est = self.files_est = 0
            todos = list(discos) + self.imagenes
            if not todos:
                self.tree.insert("", "end", text="No se encontraron discos. Probá 'Abrir imagen…'.", values=("", "", ""))
            for k, d in enumerate(todos):
                iid = f"D{k}"
                extra = [d["bus"]]
                if d.get("removable"):
                    extra.append("extraíble")
                if d.get("es_sistema"):
                    extra.append("DISCO DE WINDOWS")
                if d.get("error"):
                    extra.append("error: " + d["error"][:50])
                nombre = ("Disco %d  \u00B7  " % d["num"] if d["num"] is not None else "") + d["model"]
                self.tree.insert("", "end", iid=iid, text="\U0001F4BE  " + nombre, open=True, tags=("disk0",),
                                 values=("", fmt_size(d["size"]) if d["size"] else "?", "  \u00B7  ".join(extra)))
                for pe in self.parts_extra.get(d["path"], []):
                    if not any(x["offset"] == pe["offset"] for x in d["parts"]):
                        d["parts"].append(dict(pe))
                self.rowname[iid] = ("Disco %d" % d["num"]) if d["num"] is not None else d["model"]
                self.items[iid] = dict(kind="disk", disk=d, diskiid=iid, part=None, ok=False)
                if not d["parts"]:
                    self.tree.insert(iid, "end", text="(sin particiones detectadas)", values=("", "", ""))
                for j, p in enumerate(d["parts"]):
                    self._add_part_node(iid, d, j, p)
            self.refresh_marks()

        def _add_part_node(self, diskiid, d, j, p):
            pid = f"{diskiid}_{j}"
            n = p["num"] - 99 if p["num"] >= 100 else p["num"]
            if p["tipo"] == "sin tabla":
                nom, corto = "Disco completo (sin tabla de particiones)", "Disco completo"
            elif p["tipo"] == "volumen":
                nom, corto = "Volumen", "Volumen"
            elif p["tipo"] == "manual":
                nom, corto = "Volumen en offset manual", "Volumen manual"
            elif p["tipo"] == "encontrada":
                nom, corto = "Partición encontrada", "Encontrada"
            else:
                nom, corto = "Partición %d" % n, "Partición %d" % n
            if p["letra"]:
                nom += f"  \u00B7  unidad {p['letra']}:"
                corto = f"{p['letra']}:"
                if p["etiqueta"]:
                    nom += f' "{p["etiqueta"]}"'
            ok = p["fs"].startswith(("NTFS", "FAT", "exFAT"))
            if ok:
                det = f"{p['fs']}  \u00B7  inicio {p['offset']}"
            elif p["fs"]:
                det = p["fs"] + " (todavía no soportado)"
            else:
                det = "sistema de archivos no reconocido (¿dañado?)"
            self.tree.insert(diskiid, "end", iid=pid, text="\U0001F5C4  " + nom, tags=("part0" if ok else "bad0",),
                             values=(MARCA[0] if ok else "\u2014",
                                     fmt_size(p["length"]) if p["length"] else "?", det))
            self.rowname[pid] = corto
            if ok:
                self.tree.insert(pid, "end", iid=pid + ":d5", text="\u2026")   # marcador para poder abrirla
            self.items[pid] = dict(kind="part", disk=d, diskiid=diskiid, part=p, ok=ok)

        def _preseleccionar(self, arg):
            try:
                n, off = arg.split(":")
                n, off = int(n), int(off)
            except ValueError:
                return
            for pid, it in self.items.items():
                if it["kind"] == "part" and it["disk"]["num"] == n and it["part"]["offset"] == off:
                    self.tree.selection_set(pid)
                    self.tree.focus(pid)
                    self.tree.see(pid)
                    if it["ok"]:
                        self.tree.item(pid, open=True)
                        self._queue_load(pid)
                    return

        # ------------------------------------------------- permisos de Windows
        def _pedir_admin(self, ctx):
            """Leer discos exige administrador. Devuelve True si ya se encargo (reabrio o se cancelo)."""
            if self.admin or os.name != "nt":
                return False
            if ctx is not None and ctx[0]["num"] is None:     # imagen: no hace falta
                return False
            if not messagebox.askokcancel(
                    "Permiso de Windows",
                    "Para leer el disco, Windows pide permiso de administrador.\n\n"
                    "El programa se va a reabrir con ese permiso (te aparece un aviso de Windows).\n"
                    "Solo lee: no escribe nada en tus discos."):
                return True
            extra = ["--abrir", f"{ctx[0]['num']}:{ctx[1]['offset']}"] if ctx else []
            try:
                if relanzar_como_admin(extra):
                    self.destroy()
                    os._exit(0)
            except Exception:
                pass
            messagebox.showwarning("Sin permiso", "No se dio el permiso, así que no se puede leer ese disco.")
            return True

        # ------------------------------------------------- lectura de volumenes
        def _queue_load(self, pid):
            if pid in self.vols or pid == self.loading or pid in self.load_q or self.tarea is not None:
                return
            self.load_q.append(pid)
            self._next_load()

        def _next_load(self):
            if self.loading is not None or not self.load_q:
                self._controls()
                return
            pid = self.load_q.pop(0)
            it = self.items[pid]
            d, p = it["disk"], it["part"]
            self.loading = pid
            self.stop.clear()
            self.pb.configure(maximum=100, value=0)
            self.lbl.configure(text="Leyendo la tabla de archivos\u2026")
            threading.Thread(target=self._open_worker,
                             args=(pid, d["path"], p["offset"], p["length"], self.mft_override.get(pid)),
                             daemon=True).start()
            self._controls()

        def _open_worker(self, pid, source, off, ln, mc):
            try:
                vol = abrir_volumen(source, off, ln, mc, False,
                                    log=lambda s: self.q.put(("msg", s)),
                                    progress=lambda dn, t, u: self.q.put(("scan", (dn, t, u))),
                                    stop=self.stop)
                self.q.put(("opened", (pid, vol)))
            except Stopped:
                self.q.put(("loadfail", (pid, "Lectura detenida.")))
            except Exception as e:
                self.q.put(("loadfail", (pid, f"No pude leer ese volumen: {e}")))

        def parar(self):
            self.stop.set()
            self.load_q.clear()
            self.tick_pending = {p for p in self.tick_pending if p == self.loading}
            if self.loading is None:
                self._after_change()

        # ------------------------------------------------- arbol
        def on_open(self, _e):
            iid = self.tree.focus()
            if not iid or ":d" in iid:
                return
            if ":n" in iid:
                self._load_node(iid)
                return
            it = self.items.get(iid)
            if it and it["kind"] == "part" and it["ok"] and iid not in self.vols:
                if self.copying or self._pedir_admin((it["disk"], it["part"])):
                    self.tree.item(iid, open=False)
                    return
                self._queue_load(iid)

        def _poblar_particion(self, pid):
            for c in self.tree.get_children(pid):
                self.tree.delete(c)
            self.loaded.discard(pid)
            self._load_node(pid)
            self.tree.item(pid, open=True)

        def _load_node(self, iid):
            if iid in self.loaded:
                return
            if ":n" in iid:
                pid, _, r = iid.partition(":n")
                rid = int(r)
            else:
                pid, rid = iid, Volume.ROOT
            vol = self.vols.get(pid)
            if vol is None:
                return
            sel = self.sels[pid]
            for c in self.tree.get_children(iid):
                self.tree.delete(c)
            filas = vol.children_of(rid)
            for k, e in enumerate(filas):
                if k >= 5000:       # carpetas enormes: se muestran las primeras; tildar la carpeta las incluye todas
                    self.tree.insert(iid, "end", iid=f"{iid}:dmas", values=("", "", ""),
                                     text=f"\u2026  y {len(filas) - k} más (tildá la carpeta para recuperarlos a todos)")
                    break
                cid = f"{pid}:n{e.id}"
                if self.tree.exists(cid):
                    continue
                ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(e.mtime)) if e.mtime else ""
                size = "" if e.is_dir else (fmt_size(e.size) if e.size is not None else "?")
                borr = bool(e.borrado)
                kind = ("d" if borr else "") + ("dir" if e.is_dir else "file")
                icono = "\U0001F4C1" if e.is_dir else EXT_ICON.get(os.path.splitext(e.name)[1].lower(), "\U0001F4C4")
                info = ts
                if hasattr(vol, "info_fila"):
                    info = vol.info_fila(e.id) or info
                if borr:
                    estado = vol.info_borrado(e.id) if k < 400 else "borrado"
                    info = f"{estado}   \u00B7   {ts}" if ts else estado
                st = sel.state(e.id)
                self.tree.insert(iid, "end", iid=cid, text=f"{icono}  {e.name}", tags=(f"{kind}{st}",),
                                 values=(MARCA[st], size, info))
                self.rowkind[cid] = kind
                self.rowname[cid] = e.name
                if e.is_dir and vol.tiene_hijos(e.id):
                    self.tree.insert(cid, "end", iid=f"{pid}:d{e.id}", text="\u2026")
            self.loaded.add(iid)

        # ------------------------------------------------- casillas
        def _estado_part(self, pid):
            if pid in self.sels:
                return self.sels[pid].state(Volume.ROOT)
            return 1 if pid in self.tick_pending else 0

        def refresh_marks(self):
            for iid in list(self.loaded):
                sel = self.sels.get(iid.split(":")[0])
                if sel is None:
                    continue
                for c in self.tree.get_children(iid):
                    if ":n" in c:
                        st = sel.state(int(c.split(":n")[1]))
                        self.tree.set(c, "sel", MARCA[st])
                        self.tree.item(c, tags=(f"{self.rowkind.get(c, 'file')}{st}",))
            for iid, it in self.items.items():
                if it["kind"] == "part":
                    if it["ok"]:
                        st = self._estado_part(iid)
                        self.tree.set(iid, "sel", MARCA[st])
                        self.tree.item(iid, tags=(f"part{st}",))
                    else:
                        self.tree.item(iid, tags=("bad0",))
                else:
                    sts = [self._estado_part(k) for k, v in self.items.items()
                           if v["kind"] == "part" and v["disk"] is it["disk"] and v["ok"] and not v.get("carve")]
                    if not sts:
                        mark, st = "", 0
                    elif all(s == 1 for s in sts):
                        mark, st = MARCA[1], 1
                    elif any(s != 0 for s in sts):
                        mark, st = MARCA[2], 2
                    else:
                        mark, st = MARCA[0], 0
                    self.tree.set(iid, "sel", mark)
                    self.tree.item(iid, tags=(f"disk{st}",))

        def on_click(self, ev):
            if self.tree.identify_region(ev.x, ev.y) == "cell" and self.tree.identify_column(ev.x) == "#1":
                iid = self.tree.identify_row(ev.y)
                if iid:
                    self.toggle(iid)
                    return "break"

        def toggle(self, iid):
            if not iid or self.copying or self.tarea is not None or ":d" in iid:
                return
            if ":n" in iid:
                pid, _, rid = iid.partition(":n")
                sel = self.sels.get(pid)
                if sel is None:
                    return
                sel.toggle(int(rid))
            elif iid in self.items and self.items[iid]["kind"] == "part":
                self._tick_part(iid)
            elif iid in self.items:
                self._tick_disk(iid)
            self._after_change()

        def _set_part(self, pid, val=None):
            """Tilda/destilda una particion entera (val=None: invierte)."""
            if pid in self.sels:
                sel = self.sels[pid]
                if val is None:
                    sel.toggle(Volume.ROOT)
                else:
                    sel.explicit.clear()
                    if val:
                        sel.explicit[Volume.ROOT] = True
            else:
                want = (pid not in self.tick_pending) if val is None else val
                if want:
                    self.tick_pending.add(pid)
                    self._queue_load(pid)
                else:
                    self.tick_pending.discard(pid)

        def _tick_part(self, pid):
            it = self.items[pid]
            if not it["ok"]:
                messagebox.showinfo("No soportado", "Este tipo de partición todavía no se puede recuperar.\n"
                                    "Se soportan NTFS, FAT32, FAT16, FAT12 y exFAT.")
                return
            if pid not in self.vols and self._pedir_admin((it["disk"], it["part"])):
                return
            self._set_part(pid)

        def _tick_disk(self, iid):
            d = self.items[iid]["disk"]
            parts = [k for k, v in self.items.items()
                     if v["kind"] == "part" and v["disk"] is d and v["ok"] and not v.get("carve")]
            if not parts:
                messagebox.showinfo("Sin particiones recuperables", "Este disco no tiene particiones NTFS, FAT, FAT32 ni exFAT.")
                return
            if any(p not in self.vols for p in parts) and self._pedir_admin((d, self.items[parts[0]]["part"])):
                return
            todos = all(self._estado_part(k) == 1 for k in parts)
            for k in parts:
                self._set_part(k, not todos)

        def destildar(self):
            if self.copying:
                return
            for s in self.sels.values():
                s.clear()
            self.tick_pending.clear()
            self._after_change()

        # ------------------------------------------------- avanzado
        def abrir_manual(self):
            it = self.items.get(self.tree.focus())
            if not it:
                messagebox.showinfo("Elegí el disco", "Primero elegí la fila del disco (o de una de sus particiones).")
                return
            try:
                off = int(self.offm.get().strip())
                mc = int(self.mftc.get().strip()) if self.mftc.get().strip() else None
            except ValueError:
                messagebox.showwarning("Datos", "El offset y el cluster tienen que ser números.")
                return
            d = it["disk"]
            if self._pedir_admin((d, dict(offset=off))):
                return
            p = dict(num=0, offset=off, length=0, tipo="manual", fs="NTFS/FAT/exFAT", letra="", etiqueta="")
            d["parts"].append(p)
            j = len(d["parts"]) - 1
            self._add_part_node(it["diskiid"], d, j, p)
            pid = f"{it['diskiid']}_{j}"
            if mc:
                self.mft_override[pid] = mc
            self.tree.item(it["diskiid"], open=True)
            self.tree.item(pid, open=True)
            self._queue_load(pid)

        # ------------------------------------------------- recuperar
        def elegir_dest(self):
            p = filedialog.askdirectory(title="Carpeta donde copiar (en otro disco)")
            if p:
                self.dest.set(os.path.normpath(p))

        def recuperar(self):
            if self.copying or self.loading is not None or self.load_q or self.calc_busy:
                return
            jobs = [(pid, s) for pid, s in self.sels.items() if s.any()]
            if not jobs:
                messagebox.showinfo("Nada tildado", "Tildá un disco, una partición, carpetas o archivos.")
                return
            dest = self.dest.get().strip()
            if not dest:
                self.elegir_dest()
                dest = self.dest.get().strip()
            if not dest:
                messagebox.showwarning("Falta destino", "Elegí la carpeta donde copiar (en otro disco).")
                return
            dd = disco_de_ruta(dest)
            if dd is not None and any(self.items[pid]["disk"]["num"] == dd for pid, _ in jobs):
                messagebox.showerror("Destino inválido",
                                     "La carpeta destino está en el MISMO disco que estás recuperando.\n"
                                     "Elegí una carpeta en otro disco para no pisar datos.")
                return
            libre = self._libre_destino()
            if libre is not None and self.total_est > libre and not messagebox.askyesno(
                    "Espacio justo", f"Necesitás {fmt_size(self.total_est)} y hay {fmt_size(libre)} libres.\n"
                                     "¿Seguir igual?"):
                return
            try:
                os.makedirs(lp(dest), exist_ok=True)
            except OSError as e:
                messagebox.showerror("Destino", f"No pude crear la carpeta destino:\n{e}")
                return
            work = []
            for pid, s in jobs:
                it = self.items[pid]
                p, d = it["part"], it["disk"]
                if len(jobs) > 1:
                    n = p["num"] - 99 if p["num"] >= 100 else p["num"]
                    nm = "Disco%s_Particion%s%s" % (d["num"] if d["num"] is not None else "img", n,
                                                    ("_" + p["letra"]) if p["letra"] else "")
                    if p["tipo"] == "busqueda":
                        nm = "Disco%s_encontrados_por_contenido" % (d["num"] if d["num"] is not None else "img")
                    elif p["tipo"] == "nombre":
                        nm = "Disco%s_resultados_%s" % (d["num"] if d["num"] is not None else "img", pid.split("_")[-1])
                    out = os.path.join(dest, limpiar(nm))
                else:
                    out = dest
                work.append((self.vols[pid], s, out))
            self._apply_opts()
            self.last_dest = dest
            self.copying = True
            self.stop.clear()
            self.pb.configure(maximum=max(self.total_est, 1), value=0)
            self.say(f"Recuperando {self.files_est} archivos ({fmt_size(self.total_est)}) a {dest}")
            self._controls()
            threading.Thread(target=self._copy_worker, args=(work, self.chk_force.get()), daemon=True).start()

        def _copy_worker(self, work, force):
            try:
                tot = dict(ok=0, parcial=0, saltado=0, fallo=0, bytes=0, omitidos=0)
                for vol, sel, out in work:
                    if self.stop.is_set():
                        break
                    base = dict(tot)

                    def cb(s, r, base=base):
                        self.q.put(("prog", ({k: base[k] + s[k] for k in base}, r)))
                    st = copy_selected(vol, sel, out, self.stop, force, cb)
                    for k in tot:
                        tot[k] += st[k]
                self.q.put(("fin", tot))
            except Exception as e:
                self.q.put(("msg", f"Error inesperado: {e!r}"))
                self.q.put(("fin", None))

        # ------------------------------------------------- herramientas
        def _origen_actual(self):
            """(clave, fila) del disco o particion elegido en el arbol, o None."""
            sel = self.tree.selection()
            iid = self.tree.focus() or (sel[0] if sel else "")
            key = iid.split(":")[0] if iid else ""
            it = self.items.get(key)
            if not it or it.get("carve"):
                messagebox.showinfo("Elegí un disco", "Primero elegí en la lista un disco o una partición.")
                return None
            return key, it

        @staticmethod
        def _region(it):
            d, p = it["disk"], it["part"]
            off = p["offset"] if p else 0
            ln = (p["length"] or max(0, d["size"] - off)) if p else d["size"]
            return off, ln

        def _dialogo(self, titulo):
            sc = self.sc
            top = tk.Toplevel(self)
            top.title(titulo)
            top.configure(bg=P["bg"])
            top.transient(self)
            top.resizable(False, False)
            m = tk.Frame(top, bg=P["bg"])
            m.pack(fill="both", expand=True, padx=sc(24), pady=sc(20))
            tk.Label(m, text=titulo, bg=P["bg"], fg=P["ink"], font=("Segoe UI Semibold", 14), anchor="w").pack(fill="x")
            return top, m

        def _mostrar(self, top):
            top.update_idletasks()
            x = self.winfo_rootx() + max(0, (self.winfo_width() - top.winfo_width()) // 2)
            y = self.winfo_rooty() + max(0, (self.winfo_height() - top.winfo_height()) // 3)
            top.geometry(f"+{x}+{y}")
            try:
                top.grab_set()
            except tk.TclError:
                pass

        def _texto(self, m, txt, muted=True, **kw):
            lb = tk.Label(m, text=txt, bg=P["bg"], fg=P["muted"] if muted else P["ink"], font=("Segoe UI", 10),
                          justify="left", anchor="w", wraplength=self.sc(540), **kw)
            lb.pack(fill="x", pady=(self.sc(6), 0))
            return lb

        def dlg_contenido(self):
            r = self._origen_actual()
            if not r:
                return
            key, it = r
            p = it["part"]
            sc = self.sc
            top, m = self._dialogo("Buscar archivos por contenido")
            self._texto(m, "Encuentra fotos, videos, documentos y más por su forma, aunque ya no tengan nombre ni "
                           "carpeta (por ejemplo, después de formatear). Los nombres originales no se pueden "
                           "recuperar: los archivos salen numerados, agrupados por tipo.")
            self._texto(m, "Qué buscar", muted=False)
            fila = tk.Frame(m, bg=P["bg"])
            fila.pack(fill="x", pady=(sc(4), 0))
            gv = {g: tk.BooleanVar(value=True) for g in GRUPOS_CARVING}
            for k, g in enumerate(GRUPOS_CARVING):
                ttk.Checkbutton(fila, text=g, variable=gv[g], style="Bar.TCheckbutton").grid(
                    row=k // 3, column=k % 3, sticky="w", padx=(0, sc(18)), pady=sc(2))
            self._texto(m, "Dónde buscar", muted=False)
            libre_ok = bool(p and it["ok"])
            amb = tk.StringVar(value="libre" if libre_ok else "todo")
            rb = ttk.Radiobutton(m, text="Solo en el espacio libre  (rápido; ideal para archivos borrados)",
                                 variable=amb, value="libre", style="Bar.TRadiobutton",
                                 state="normal" if libre_ok else "disabled")
            rb.pack(anchor="w", pady=(sc(4), 0))
            ttk.Radiobutton(m, text="En todo el disco o partición  (lento; sirve si se formateó o el sistema "
                                    "de archivos está dañado)", variable=amb, value="todo",
                            style="Bar.TRadiobutton").pack(anchor="w", pady=(sc(2), 0))
            f2 = tk.Frame(m, bg=P["bg"])
            f2.pack(fill="x", pady=(sc(12), 0))
            tk.Label(f2, text="Ignorar archivos menores a", bg=P["bg"], fg=P["ink"], font=("Segoe UI", 10)).pack(side="left")
            kb = tk.StringVar(value="10")
            ttk.Spinbox(f2, from_=0, to=1000000, width=8, textvariable=kb).pack(side="left", padx=sc(8))
            tk.Label(f2, text="KB", bg=P["bg"], fg=P["ink"], font=("Segoe UI", 10)).pack(side="left")
            rec = tk.BooleanVar(value=False)
            ttk.Checkbutton(m, text="Reconstruir fotos JPEG fragmentadas  (mucho más lento; rearma fotos partidas en "
                                    "varios pedazos)", variable=rec, style="Bar.TCheckbutton").pack(
                anchor="w", pady=(sc(12), 0))
            fb = tk.Frame(m, bg=P["bg"])
            fb.pack(fill="x", pady=(sc(18), 0))

            def empezar():
                gs = [g for g in GRUPOS_CARVING if gv[g].get()]
                if not gs:
                    messagebox.showinfo("Qué buscar", "Marcá al menos un tipo de archivo.", parent=top)
                    return
                try:
                    k_ = max(0, int(kb.get().strip() or 0))
                except ValueError:
                    k_ = 10
                top.destroy()
                self._lanzar_contenido(key, gs, amb.get(), k_, rec.get())
            ttk.Button(fb, text="Empezar a buscar", style="Accent.TButton", command=empezar).pack(side="right")
            ttk.Button(fb, text="Cancelar", command=top.destroy).pack(side="right", padx=(0, sc(10)))
            self._mostrar(top)

        def dlg_particiones(self):
            r = self._origen_actual()
            if not r:
                return
            key, it = r
            d = it["disk"]
            sc = self.sc
            top, m = self._dialogo("Buscar particiones perdidas")
            self._texto(m, "Si el disco aparece sin particiones, como \"sin formato\" o con el tamaño equivocado, "
                           "esto recorre el disco entero buscando los inicios de particiones NTFS, FAT32, FAT16/12 y exFAT, "
                           "aunque la tabla de particiones esté borrada. Las que encuentre se agregan a la lista "
                           "para que puedas recuperar sus archivos.")
            self._texto(m, f"Se va a leer todo el disco ({fmt_size(d['size'])}). Puede tardar bastante en discos "
                           "grandes; podés parar cuando quieras y se conserva lo encontrado hasta ahí.", muted=False)
            fb = tk.Frame(m, bg=P["bg"])
            fb.pack(fill="x", pady=(sc(18), 0))

            def empezar():
                top.destroy()
                self._lanzar_particiones(it["diskiid"])
            ttk.Button(fb, text="Empezar a buscar", style="Accent.TButton", command=empezar).pack(side="right")
            ttk.Button(fb, text="Cancelar", command=top.destroy).pack(side="right", padx=(0, sc(10)))
            self._mostrar(top)

        def dlg_imagen(self):
            r = self._origen_actual()
            if not r:
                return
            key, it = r
            d, p = it["disk"], it["part"]
            off, ln = self._region(it)
            sug = ("disco%s" % d["num"] if d["num"] is not None else "imagen") + ("_particion" if p else "") + ".img"
            if not messagebox.askokcancel(
                    "Crear imagen (copia segura)",
                    f"Se va a copiar {fmt_size(ln)} a un archivo de imagen. Es lo más seguro cuando un disco "
                    "falla: después se recupera desde la copia sin forzar más el disco original.\n\n"
                    "Copia por fases: primero lo que se lee bien (rápido) y recién después, con cuidado, las zonas "
                    "dañadas. Los sectores que no se puedan leer quedan en ceros y se anotan. Si la parás, "
                    "podés seguir después desde el mismo punto.\n\n"
                    "A continuación elegís dónde guardarla (en OTRO disco)."):
                return
            dest = filedialog.asksaveasfilename(title="Guardar imagen como\u2026", defaultextension=".img",
                                                initialfile=sug, filetypes=[("Imagen de disco", "*.img"),
                                                                            ("Todos los archivos", "*.*")])
            if dest:
                self._lanzar_imagen(key, os.path.normpath(dest))

        # ---- tareas largas en segundo plano
        def _iniciar_tarea(self, nombre, fn, args, texto):
            self.tarea = nombre
            self.stop.clear()
            self.pb.configure(maximum=100, value=0)
            self.lbl.configure(text=texto)
            self._controls()
            threading.Thread(target=self._tarea_worker, args=(nombre, fn, args), daemon=True).start()

        def _tarea_worker(self, nombre, fn, args):
            try:
                self.q.put(("tarea_fin", (nombre, fn(*args))))
            except Exception as e:
                self.q.put(("tarea_fin", (nombre, e)))

        def _lanzar_contenido(self, key, grupos, ambito, min_kb, reconstruir=False):
            it = self.items[key]
            if self._pedir_admin((it["disk"], it["part"] or dict(offset=0))):
                return
            self._iniciar_tarea("contenido", self._t_contenido, (key, list(grupos), ambito, min_kb, reconstruir),
                                "Preparando la búsqueda\u2026")

        def _t_contenido(self, key, grupos, ambito, min_kb, reconstruir=False):
            it = self.items[key]
            d, p = it["disk"], it["part"]
            off, ln = self._region(it)
            limite = off + ln
            src = RawSource(d["path"])
            rangos, nota, libre, unidad = [(off, ln)], "", False, 4096
            if ambito == "libre" and p and it["ok"]:
                try:
                    vol = self.vols.get(key)
                    propio = vol is None
                    if propio:
                        vol = abrir_volumen(d["path"], off, p["length"], self.mft_override.get(key), False,
                                            log=lambda s: None, progress=None, stop=self.stop)
                    try:
                        lib = rangos_libres(vol)
                        unidad = max(512, int(getattr(vol, "cs", 4096) or 4096))
                    finally:
                        if propio:
                            vol.src.close()
                    if lib is None:
                        nota = "No se pudo leer el mapa de espacio libre: se buscó en todo."
                    else:
                        rangos, libre = lib, True
                except Stopped:
                    src.close()
                    return dict(hits=[], completo=False, src=None, key=key, nota="", libre=False)
                except Exception as e:
                    nota = f"No se pudo leer el sistema de archivos ({e}): se buscó en todo."
            hits, completo = carve(src, rangos, limite, grupos, max(0, int(min_kb)) * 1024, self.stop,
                                   lambda a, b, c: self.q.put(("tarea_prog", ("contenido", a, b, c, 0))),
                                   reconstruir=reconstruir, unidad=unidad)
            return dict(hits=hits, completo=completo, src=src, key=key, nota=nota, libre=libre)

        def _lanzar_particiones(self, diskiid):
            d = self.items[diskiid]["disk"]
            if self._pedir_admin((d, dict(offset=0))):
                return
            self._iniciar_tarea("particiones", self._t_particiones, (diskiid,), "Buscando particiones\u2026")

        def _t_particiones(self, diskiid):
            d = self.items[diskiid]["disk"]
            src = RawSource(d["path"])
            try:
                res = buscar_particiones(src, d["size"], self.stop,
                                         lambda a, b, c: self.q.put(("tarea_prog", ("particiones", a, b, c, 0))))
            finally:
                src.close()
            return dict(parts=res, diskiid=diskiid, completo=not self.stop.is_set())

        def _lanzar_imagen(self, key, dest, reanudar=None):
            it = self.items[key]
            d, p = it["disk"], it["part"]
            off, ln = self._region(it)
            if self._pedir_admin((d, p or dict(offset=0))):
                return
            dd = disco_de_ruta(dest)
            if dd is not None and d["num"] == dd:
                messagebox.showerror("Destino inválido", "La imagen no puede guardarse en el MISMO disco que "
                                     "estás copiando. Elegí otro disco.")
                return
            existe = os.path.exists(dest)
            if reanudar is None:
                reanudar = True
                if existe:
                    r = messagebox.askyesnocancel(
                        "La imagen ya existe", "Ya hay un archivo con ese nombre.\n\n"
                        "Sí = continuar la copia anterior\nNo = empezar de nuevo (se sobrescribe)")
                    if r is None:
                        return
                    reanudar = bool(r)
            carpeta = os.path.dirname(os.path.abspath(dest))
            try:
                libre = shutil.disk_usage(carpeta).free
            except OSError:
                libre = None
            ya = os.path.getsize(dest) if (existe and reanudar) else 0
            if libre is not None and ln - ya > libre and not messagebox.askyesno(
                    "Espacio justo", f"La imagen necesita {fmt_size(ln - ya)} y hay {fmt_size(libre)} libres.\n"
                                     "¿Seguir igual?"):
                return
            self._iniciar_tarea("imagen", self._t_imagen, (key, dest, reanudar), "Copiando el disco\u2026")

        def _t_imagen(self, key, dest, reanudar):
            it = self.items[key]
            d = it["disk"]
            off, ln = self._region(it)
            src = RawSource(d["path"])
            try:
                res = clonar_fases(src, dest, off, ln, self.stop,
                                   lambda a, b, c, v, f: self.q.put(("tarea_prog", ("imagen", a, b, c, v, f))), reanudar)
            finally:
                src.close()
            return dict(res=res, dest=dest)

        def _prog_tarea(self, v):
            nombre, a, b, c, vel, *resto = v
            fase = {"copiar": "copiando lo sano", "recortar": "recortando zonas dañadas",
                    "raspar": "leyendo sector por sector", "reintentar": "reintentando sectores ilegibles"
                    }.get(resto[0] if resto else "", "")
            self.pb.configure(maximum=max(b, 1), value=min(a, max(b, 1)))
            pct = int(100 * a / max(b, 1))
            if nombre == "contenido":
                self.lbl.configure(text=f"Buscando por contenido: {pct}%  \u00B7  {c} archivos encontrados")
            elif nombre == "nombre":
                self.pb.configure(value=0)
                self.lbl.configure(text=f"Buscando por nombre: {a} carpetas revisadas  \u00B7  {c} coincidencias")
            elif nombre == "particiones":
                self.lbl.configure(text=f"Buscando particiones: {pct}%  \u00B7  {c} candidatas")
            else:
                self.lbl.configure(text=f"Copiando ({fase}): {pct}%  \u00B7  {fmt_size(int(vel))}/s  \u00B7  "
                                        f"{c} sectores ilegibles")

        def _fin_tarea(self, v):
            nombre, res = v
            self.tarea = None
            self.pb.configure(value=0)
            self._controls()
            if isinstance(res, Exception):
                self.say(f"No pude completar la tarea: {res}")
                messagebox.showerror("Error", f"No se pudo completar:\n{res}")
            elif nombre == "contenido":
                self._fin_contenido(res)
            elif nombre == "nombre":
                self._fin_nombre(res)
            elif nombre == "particiones":
                self._fin_particiones(res)
            else:
                self._fin_imagen(res)

        # ------------------------------------------------- busqueda por nombre
        def _volumenes_busqueda(self):
            """Particiones ya leidas donde buscar: la de la fila elegida, o todas las leidas."""
            reales = [k for k, v in self.vols.items() if not self.items.get(k, {}).get("carve")]
            sel = self.tree.selection()
            iid = sel[0] if sel else None
            while iid:
                if iid in reales:
                    return [iid]
                iid = self.tree.parent(iid)
            return reales

        def buscar_por_nombre(self):
            if self.copying or self.loading is not None or self.load_q or self.tarea is not None:
                return
            q = self.q_name.get().strip()
            if not q:
                return
            objetivos = self._volumenes_busqueda()
            if not objetivos:
                messagebox.showinfo("Buscar por nombre",
                                    "Primero abrí una partición (clic en su flecha o en su casilla) para poder buscar en ella.")
                return
            self._iniciar_tarea("nombre", self._t_nombre, (objetivos, q), "Buscando por nombre\u2026")

        def _t_nombre(self, objetivos, q):
            out = []
            for pid in objetivos:
                vol = self.vols[pid]
                hits, completo = buscar_nombre(
                    vol, q, True, self.stop,
                    lambda a, c: self.q.put(("tarea_prog", ("nombre", a, 1, c, 0))))
                out.append((pid, hits, completo))
                if self.stop.is_set():
                    break
            return dict(res=out, q=q)

        def _fin_nombre(self, r):
            total, borr = 0, 0
            for pid, hits, completo in r["res"]:
                if not hits:
                    continue
                self._add_search_node(pid, hits, r["q"])
                total += len(hits)
                borr += sum(1 for h in hits if h["borrado"])
            if not total:
                self.lbl.configure(text="Sin coincidencias.")
                messagebox.showinfo("Buscar por nombre", f"No encontré nada que coincida con \u201C{r['q']}\u201D.")
                return
            extra = ""
            if borr and not self.show_del.get():
                extra = f" {borr} son archivos borrados: activá \u201CIncluir archivos borrados\u201D para verlos."
            if any(not c for _, _, c in r["res"]):
                extra += " (La búsqueda se detuvo antes de terminar.)"
            self.say(f"Búsqueda por nombre \u201C{r['q']}\u201D: {total} coincidencias.{extra}")
            self.lbl.configure(text=f"{total} coincidencias.{extra} Tildá lo que quieras recuperar.")

        def _add_search_node(self, realpid, hits, consulta):
            it0 = self.items[realpid]
            diskiid, d = it0["diskiid"], it0["disk"]
            k = sum(1 for i in self.items if i.startswith(diskiid + "_s"))
            pid = f"{diskiid}_s{k}"
            vol = SearchVolume(self.vols[realpid], hits, consulta)
            vol.set_borrados(self.show_del.get())
            p = dict(num=0, offset=0, length=0, tipo="nombre", fs="resultados", letra="", etiqueta="")
            n_vis = len(vol.children_of(Volume.ROOT))
            origen = self.rowname.get(realpid, "partición")
            self.tree.insert(diskiid, "end", iid=pid, tags=("part0",),
                             text=f"\U0001F50D  Resultados de \u201C{consulta}\u201D  ({len(hits)})",
                             values=(MARCA[0], "", f"búsqueda por nombre en {origen}"))
            self.rowname[pid] = f"Resultados de “{consulta}”"
            self.items[pid] = dict(kind="part", disk=d, diskiid=diskiid, part=p, ok=True, carve=True, busqueda_nombre=True)
            self.vols[pid] = vol
            self.sels[pid] = Selection(vol)
            self.tree.insert(pid, "end", iid=pid + ":d5", text="\u2026")
            self._poblar_particion(pid)
            self.tree.item(diskiid, open=True)
            self.tree.see(pid)
            self.refresh_marks()

        def _fin_contenido(self, res):
            hits = res["hits"]
            ambito = "en el espacio libre" if res["libre"] else "en todo el disco o partición"
            nota = ("\n" + res["nota"]) if res["nota"] else ""
            parado = "" if res["completo"] else " (detenida: son los encontrados hasta ahí)"
            if not hits:
                if res["src"] is not None:
                    res["src"].close()
                self.lbl.configure(text="Búsqueda terminada: no se encontraron archivos.")
                messagebox.showinfo("Búsqueda terminada", f"No se encontraron archivos de los tipos elegidos "
                                    f"{ambito}.{nota}")
                return
            self.carve_srcs.append(res["src"])
            it = self.items[res["key"]]
            self._add_carve_node(it["diskiid"], it["disk"], res)
            self.say(f"Búsqueda por contenido{parado}: {len(hits)} archivos {ambito}.{nota.replace(chr(10), ' ')}")
            self.lbl.configure(text=f"{len(hits)} archivos encontrados por contenido. Tildá lo que quieras recuperar.")

        def _add_carve_node(self, diskiid, d, res):
            hits = res["hits"]
            k = sum(1 for i in self.items if i.startswith(diskiid + "_c"))
            pid = f"{diskiid}_c{k}"
            p = dict(num=0, offset=0, length=sum(h["length"] for h in hits), tipo="busqueda", fs="resultados",
                     letra="", etiqueta="")
            vol = CarveVolume(res["src"], hits)
            tipos = len({h["grupo"] for h in hits})
            self.tree.insert(diskiid, "end", iid=pid, tags=("part0",),
                             text=f"\U0001F50E  Encontrados por contenido ({len(hits)} archivos)",
                             values=(MARCA[0], fmt_size(p["length"]),
                                     "búsqueda por contenido  \u00B7  %d tipos de archivo" % tipos))
            self.rowname[pid] = "Encontrados por contenido"
            self.items[pid] = dict(kind="part", disk=d, diskiid=diskiid, part=p, ok=True, carve=True)
            self.vols[pid] = vol
            self.sels[pid] = Selection(vol)
            vol.set_borrados(self.show_del.get())
            self.tree.insert(pid, "end", iid=pid + ":d5", text="\u2026")
            self._poblar_particion(pid)
            self.tree.item(diskiid, open=True)
            self.tree.see(pid)
            self.refresh_marks()

        def _fin_particiones(self, res):
            diskiid = res["diskiid"]
            d = self.items[diskiid]["disk"]
            nuevos = [q_ for q_ in res["parts"] if not any(p["offset"] == q_["offset"] for p in d["parts"])]
            for ph in list(self.tree.get_children(diskiid)):
                if self.tree.item(ph, "text").startswith("(sin particiones") and nuevos:
                    self.tree.delete(ph)
            for q_ in nuevos:
                fs = q_["fs"] + (" (arranque perdido)" if q_["nota"] else "")
                p = dict(num=0, offset=q_["offset"], length=q_["length"], tipo="encontrada", fs=fs, letra="",
                         etiqueta="")
                d["parts"].append(p)
                self.parts_extra.setdefault(d["path"], []).append(dict(p))
                self._add_part_node(diskiid, d, len(d["parts"]) - 1, p)
            self.tree.item(diskiid, open=True)
            self.refresh_marks()
            parado = "" if res["completo"] else " (búsqueda detenida)"
            if nuevos:
                txt = f"Se encontraron {len(nuevos)} particiones nuevas{parado}. Ya están en la lista."
            elif res["parts"]:
                txt = f"Se encontraron {len(res['parts'])} particiones, pero ya estaban en la lista{parado}."
            else:
                txt = f"No se encontraron particiones NTFS, FAT ni exFAT{parado}."
            self.say(txt)
            self.lbl.configure(text=txt)
            messagebox.showinfo("Búsqueda de particiones", txt)

        def _fin_imagen(self, res):
            r, dest = res["res"], res["dest"]
            malos = len(r["malos"])
            extra = f"\nSectores ilegibles: {malos} (anotados en {os.path.basename(dest)}.malos.txt)" if malos else \
                "\nNo hubo sectores ilegibles."
            if r["estado"] == "completo":
                self.say(f"Imagen creada: {dest}.{extra.replace(chr(10), ' ')}")
                if messagebox.askyesno("Imagen creada", f"La copia terminó.{extra}\n\n"
                                       "¿Agregarla a la lista para recuperar desde ella?"):
                    try:
                        self.imagenes.append(info_imagen(dest))
                    except Exception as e:
                        messagebox.showerror("Error", f"No pude abrir la imagen:\n{e}")
                    self.refrescar()
            else:
                self.say(f"Copia detenida en {fmt_size(r['copiado'])}. Para seguir, elegí el mismo archivo de destino.")
                messagebox.showinfo("Copia detenida", "Podés continuar más tarde eligiendo el mismo archivo "
                                    "de destino y la opción 'Sí' al preguntar.")

        # ----------------------------------------------------- cola UI
        def _poll(self):
            try:
                while True:
                    k, v = self.q.get_nowait()
                    if k == "msg":
                        self.say(v)
                    elif k == "discos":
                        self._fill_discos(v)
                        self.lbl.configure(text="Elegí qué recuperar: tildá un disco, una partición o carpetas.")
                        if self.abrir_arg:
                            self._preseleccionar(self.abrir_arg)
                            self.abrir_arg = None
                        self._after_change()
                    elif k == "scan":
                        dn, t, u = v
                        self.pb.configure(maximum=max(t, 1), value=dn)
                        self.lbl.configure(text=f"Leyendo el disco: {dn}/{t} | {u} archivos y carpetas")
                    elif k == "opened":
                        pid, vol = v
                        vol.set_borrados(self.show_del.get())
                        self.vols[pid] = vol
                        self.sels[pid] = Selection(vol)
                        self.loading = None
                        self.pb.configure(value=0)
                        self._poblar_particion(pid)
                        if pid in self.tick_pending:
                            self.tick_pending.discard(pid)
                            self.sels[pid].explicit[Volume.ROOT] = True
                        self.lbl.configure(text="Listo. Tildá lo que quieras recuperar.")
                        self._next_load()
                        self._after_change()
                    elif k == "loadfail":
                        pid, msg = v
                        self.say(msg)
                        self.loading = None
                        self.tick_pending.discard(pid)
                        if self.tree.exists(pid):
                            self.tree.item(pid, open=False)
                        self._next_load()
                        self._after_change()
                    elif k == "tarea_prog":
                        self._prog_tarea(v)
                    elif k == "tarea_fin":
                        self._fin_tarea(v)
                    elif k == "calc":
                        gen, files, total = v
                        if gen != self.calc_gen:
                            continue
                        self.calc_busy = False
                        self.files_est, self.total_est = files, total
                        self._update_summary()
                        self._controls()
                    elif k == "prog":
                        s, r = v
                        self.pb.configure(value=min(s["bytes"], self.pb["maximum"]))
                        self.lbl.configure(text=f"OK {s['ok']} | parciales {s['parcial']} | fallos {s['fallo']} | "
                                                f"ya estaban {s['saltado']} | omitidos {s['omitidos']} | "
                                                f"{fmt_size(s['bytes'])}  <- {r[-60:]}")
                    elif k == "fin":
                        self.copying = False
                        self._controls()
                        if v is None:
                            continue
                        resumen = (f"Recuperados: {v['ok']}  |  parciales: {v['parcial']}  |  "
                                   f"ya estaban: {v['saltado']}  |  fallos: {v['fallo']}  |  "
                                   f"omitidos (cifrados, comprimidos o sobrescritos): {v['omitidos']}  |  {fmt_size(v['bytes'])}")
                        parado = " (parado)" if self.stop.is_set() else ""
                        self.say(f"Terminado{parado}: {resumen}. Detalle en recuperacion_log.csv dentro del destino.")
                        if messagebox.askyesno("Terminado" + parado, resumen + "\n\n¿Abrir la carpeta de destino?"):
                            try:
                                os.startfile(self.last_dest)
                            except Exception:
                                pass
            except queue.Empty:
                pass
            self.after(150, self._poll)

    App().mainloop()


def main():
    ap = argparse.ArgumentParser(description="Reflota: recuperador NTFS por MFT (solo lectura, gratis).")
    ap.add_argument("--source", help=r"Ej: \\.\PhysicalDrive5 o C:\imagen.img")
    ap.add_argument("--particiones", action="store_true", help="Solo listar particiones")
    ap.add_argument("--offset", type=int, help="Offset en bytes del volumen NTFS")
    ap.add_argument("--length", type=int, default=0, help="Largo del volumen en bytes (opcional)")
    ap.add_argument("--mft-cluster", type=int, help="Cluster de la MFT si el sector de arranque esta danado")
    ap.add_argument("--ls", help="Listar una ruta, ej: /Programacion")
    ap.add_argument("--copiar", help="Ruta a copiar, ej: /MisDocumentos/Fotos")
    ap.add_argument("--dest", help="Carpeta destino (en OTRO disco)")
    ap.add_argument("--forzar", action="store_true", help="Recopiar aunque ya exista")
    ap.add_argument("--sin-cache", action="store_true", help="No usar indice guardado")
    ap.add_argument("--borrados", action="store_true", help="Incluir archivos borrados al listar/copiar")
    ap.add_argument("--abrir", help=argparse.SUPPRESS)     # uso interno: "disco:offset" al reabrir con permisos
    args = ap.parse_args()
    if args.source:
        sys.exit(cli(args))
    run_gui(args.abrir)


if __name__ == "__main__":
    main()
