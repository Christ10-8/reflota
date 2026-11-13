"""tkinter simulado (el sandbox no trae tkinter): suficiente para ejecutar la logica de la GUI de Reflota."""
import sys, types

class _S:
    def __init__(self, *a, **k): pass
    def __getattr__(self, n):
        if n.startswith("__"): raise AttributeError(n)
        return _S()
    def __call__(self, *a, **k): return _S()
    def __setitem__(self, k, v): pass
    def __getitem__(self, k): return _S()
    def __iter__(self): return iter(())
    def __contains__(self, x): return False

class Tk(_S):
    last = None
    def __init__(self, *a, **k): Tk.last = self
    def winfo_fpixels(self, _): return 96.0
    def winfo_screenwidth(self): return 1920
    def winfo_screenheight(self): return 1080
    def after(self, *a, **k): return "x"
    def mainloop(self): pass

class _Var:
    DEF = ""
    def __init__(self, master=None, value=None, **k): self.v = self.DEF if value is None else value
    def get(self): return self.v
    def set(self, v): self.v = v
    def trace_add(self, *a): pass

class _BVar(_Var):
    DEF = False
class _IVar(_Var):
    DEF = 0

class Bar(_S):
    def __init__(self, *a, **k): self.o = {"maximum": 100, "value": 0}
    def configure(self, **k): self.o.update(k)
    config = configure
    def __getitem__(self, k): return self.o.get(k, 0)

class Tree(_S):
    COLS = ("sel", "size", "info")
    def __init__(self, *a, **k):
        self.nodes = {"": dict(children=[], parent=None)}
        self.sel = []
    def insert(self, parent, index, iid=None, **kw):
        iid = iid or f"I{len(self.nodes)}"
        assert parent in self.nodes, f"padre inexistente {parent!r} al insertar {iid!r}"
        assert iid not in self.nodes, f"iid repetido {iid!r}"
        self.nodes[iid] = dict(children=[], parent=parent, text=kw.get("text", ""), values=list(kw.get("values", ("", "", ""))),
                               tags=tuple(kw.get("tags", ())), open=kw.get("open", False))
        self.nodes[parent]["children"].append(iid)
        return iid
    def _borrar(self, iid):
        for c in list(self.nodes[iid]["children"]): self._borrar(c)
        p = self.nodes[iid]["parent"]
        if p in self.nodes and iid in self.nodes[p]["children"]: self.nodes[p]["children"].remove(iid)
        del self.nodes[iid]
    def delete(self, *ids):
        for i in ids:
            if i in self.nodes: self._borrar(i)
    def get_children(self, iid=""): return tuple(self.nodes[iid]["children"])
    def exists(self, iid): return iid in self.nodes
    def parent(self, iid): return self.nodes[iid]["parent"] or ""
    def item(self, iid, option=None, **kw):
        n = self.nodes[iid]
        if kw:
            for k, v in kw.items(): n[k] = v
            return None
        return n[option] if option else dict(n)
    def set(self, iid, col, val=None):
        n = self.nodes[iid]
        if val is None: return n["values"][self.COLS.index(col)]
        n["values"][self.COLS.index(col)] = val
    def selection(self): return tuple(self.sel)
    def selection_set(self, i): self.sel = [i]
    def focus(self, i=None): return i or ""
    def see(self, i): pass

class _Msg:
    log = []
    @staticmethod
    def _f(nombre, ret=None):
        def f(*a, **k):
            _Msg.log.append((nombre, a))
            return ret
        return f

def instalar():
    tk = types.ModuleType("tkinter")
    for n in ("Frame", "Label", "Canvas", "Text", "Menu", "Toplevel", "PhotoImage", "Scrollbar", "Button", "Entry"):
        setattr(tk, n, _S)
    tk.Tk, tk.StringVar, tk.BooleanVar, tk.IntVar = Tk, _Var, _BVar, _IVar
    tk.TclError = Exception
    ttk = types.ModuleType("tkinter.ttk")
    for n in ("Button", "Entry", "Checkbutton", "Scrollbar", "Style", "Menubutton", "Label", "Frame", "Combobox", "Radiobutton", "Spinbox"):
        setattr(ttk, n, _S)
    ttk.Treeview, ttk.Progressbar = Tree, Bar
    fd = types.ModuleType("tkinter.filedialog")
    for n in ("askdirectory", "askopenfilename", "asksaveasfilename"): setattr(fd, n, lambda *a, **k: "")
    mb = types.ModuleType("tkinter.messagebox")
    for n in ("showinfo", "showwarning", "showerror"): setattr(mb, n, _Msg._f(n))
    for n in ("askyesno", "askokcancel", "askretrycancel"): setattr(mb, n, _Msg._f(n, True))
    tk.ttk, tk.filedialog, tk.messagebox = ttk, fd, mb
    sys.modules.update({"tkinter": tk, "tkinter.ttk": ttk, "tkinter.filedialog": fd, "tkinter.messagebox": mb})
    return _Msg
