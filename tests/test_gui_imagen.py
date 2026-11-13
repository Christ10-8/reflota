import os, tempfile
TMP = tempfile.gettempdir()
import sys, os, time, importlib.util
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fake_tk
Msg = fake_tk.instalar()
spec = importlib.util.spec_from_file_location("reflota", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reflota.py"))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
R.run_gui(); app = fake_tk.Tk.last
def bombear(c, t=30):
    t0 = time.time()
    while time.time() - t0 < t:
        app._poll()
        if c(): return True
        time.sleep(0.05)
    return False
app._fill_discos([R.info_imagen(TMP + "/busq.img")])
pid = [k for k, v in app.items.items() if v["kind"] == "part"][0]
for e in ("", ".mapa", ".origen"):
    if os.path.exists(TMP + "/gui_clon.img" + e): os.remove(TMP + "/gui_clon.img" + e)
app._lanzar_imagen(pid, TMP + "/gui_clon.img")
ok = bombear(lambda: app.tarea is None and os.path.exists(TMP + "/gui_clon.img.mapa"))
print("terminó:", ok, "| etiqueta:", app.lbl.o if hasattr(app.lbl, "o") else "")
same = open(TMP + "/gui_clon.img", "rb").read() == open(TMP + "/busq.img", "rb").read()
print("OK  " if ok and same else "FALLA", "imagen idéntica desde la GUI:", same)
print([m for m in Msg.log if m[0] in ("askyesno", "showinfo", "showerror")][-2:])
