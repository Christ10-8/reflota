import os, tempfile
TMP = tempfile.gettempdir()
import sys, os, time, importlib.util
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fake_tk
Msg = fake_tk.instalar()
spec = importlib.util.spec_from_file_location("reflota", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reflota.py"))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
R.run_gui(); app = fake_tk.Tk.last
def bombear(c, t=120):
    t0 = time.time()
    while time.time() - t0 < t:
        app._poll()
        if c(): return True
        time.sleep(0.05)
    return False
app._fill_discos([R.info_imagen(TMP + "/frag_disco.img")])
key = list(app.items)[0]
app._lanzar_contenido(key, ["Fotos"], "todo", 2, True)
ok = bombear(lambda: app.tarea is None and any(i.endswith("_c0") for i in app.items))
nodo = [i for i in app.items if i.endswith("_c0")][0]
hij = app.tree.get_children(nodo)
print("nodo:", app.tree.nodes[nodo]["text"])
grupo = app.tree.get_children(nodo)
filas = []
def hojas(i):
    for c in app.tree.get_children(i):
        if c.endswith(":dmas") or app.tree.nodes[c]["text"] == "\u2026": continue
        filas.append(c); 
app._load_node(nodo)
for g in app.tree.get_children(nodo):
    if ":d" in g: continue
    app.tree.item(g, open=True); app._load_node(g)
    for c in app.tree.get_children(g): filas.append(app.tree.nodes[c]["values"][2])
print(filas)
print("OK  " if ok and sum("fragmentos" in f for f in filas) == 2 else "FALLA", "GUI: 3 fotos, 2 reconstruidas")
