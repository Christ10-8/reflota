import os, tempfile
TMP = tempfile.gettempdir()
import sys, os, time, hashlib, shutil, importlib.util
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fake_tk
Msg = fake_tk.instalar()
spec = importlib.util.spec_from_file_location("reflota", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reflota.py"))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
R.run_gui()
app = fake_tk.Tk.last
fallos = []
def chk(c, m):
    print(("OK   " if c else "FALLA"), m)
    if not c: fallos.append(m)
def bombear(cond, t=30):
    t0 = time.time()
    while time.time() - t0 < t:
        app._poll()
        if cond(): return True
        time.sleep(0.05)
    return False

d = R.info_imagen(TMP + "/busq.img")
app._fill_discos([d])
print("filas:", list(app.tree.nodes)[:8])
pid = [k for k, v in app.items.items() if v["kind"] == "part"][0]
app._tick_part(pid)
chk(bombear(lambda: pid in app.vols and app.loading is None), f"partición {pid} leída")
# --- buscar
app.q_name.set("factura")
app.tree.sel = [pid]
app.buscar_por_nombre()
chk(bombear(lambda: app.tarea is None and any(i.endswith("_s0") for i in app.items)), "tarea de búsqueda terminó y creó nodo")
sp = [i for i in app.items if i.endswith("_s0")][0]
print("nodo:", app.tree.nodes[sp]["text"], app.tree.nodes[sp]["values"])
hijos = app.tree.get_children(sp)
print("hijos:", [app.tree.nodes[h]["text"] for h in hijos])
chk(len(hijos) >= 3, "resultados visibles (borrados ocultos hasta activar la opción)")
app.show_del.set(True)
app._toggle_borrados()
hijos = app.tree.get_children(sp)
print("hijos con borrados:", [app.tree.nodes[h]["text"] for h in hijos])
chk(any("vieja" in app.tree.nodes[h]["text"].lower() for h in hijos), "al activar borrados aparece 'Factura vieja' en los resultados")
# --- tildar un resultado de archivo y la carpeta, recuperar
app.destildar()
marcar = [h for h in hijos if "factura marzo" in app.tree.nodes[h]["text"]][0]
app.toggle(marcar)
chk(app.sels[sp].any(), "resultado tildado")
app._recalc()
bombear(lambda: not app.calc_busy)
print("estimado:", app.files_est, app.total_est)
chk(app.files_est == 1 and app.total_est == 9000, "tamaño estimado de la selección")
dest = TMP + "/gui_dest"; shutil.rmtree(dest, ignore_errors=True)
app.dest.set(dest)
app.recuperar()
chk(bombear(lambda: not app.copying and any(f.endswith("factura marzo.pdf") for _, _, fs in os.walk(dest) for f in fs)), "copia terminó")
ruta = [os.path.join(a, f) for a, _, fs in os.walk(dest) for f in fs if f.endswith(".pdf")]
print("copiado:", ruta)
orig = open(TMP + "/busq.img", "rb").read()
chk(len(ruta) == 1 and os.path.getsize(ruta[0]) == 9000, "archivo copiado con el tamaño correcto")
# búsqueda sin resultados y consulta vacía
n_antes = len(app.items)
app.q_name.set("zzzz_no_existe"); app.buscar_por_nombre()
bombear(lambda: app.tarea is None)
chk(len(app.items) == n_antes and any(m[0] == "showinfo" for m in Msg.log), "sin coincidencias: aviso y sin nodo nuevo")
app.q_name.set("  "); app.buscar_por_nombre()
chk(app.tarea is None, "consulta vacía no hace nada")
# sin partición abierta
app._fill_discos([R.info_imagen(TMP + "/busq.img")])
app.q_name.set("factura"); Msg.log.clear(); app.buscar_por_nombre()
chk(app.tarea is None and Msg.log and Msg.log[-1][0] == "showinfo", "sin partición abierta: avisa")
print("\nFALLOS:", fallos or "ninguno")
