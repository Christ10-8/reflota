"""Prueba con ventana REAL de tkinter (no simulada): que el pie de la ventana se vea completo.
Antes del arreglo, en pantallas de 1366x768 o 1280x720 el boton RECUPERAR y el registro quedaban aplastados.
Necesita pantalla (en Windows funciona tal cual; en Linux:  xvfb-run -s "-screen 0 1366x768x24" python test_gui_layout_real.py).
Si no hay pantalla, se omite sin error."""
import importlib.util, os, sys, time
try:
    import tkinter
    _t = tkinter.Tk(); _t.destroy()
except Exception as e:                          # sin tkinter o sin pantalla
    print("OMITIDA: no hay pantalla/tkinter disponible:", e); sys.exit(0)
spec = importlib.util.spec_from_file_location("reflota", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reflota.py"))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
R.listar_todo = lambda admin=True: []           # sin discos: solo se mide la distribucion
R.es_admin = lambda: True
fallos = []
def chk(n, c, x=""):
    print(("OK   " if c else "FALLA"), n, x)
    if not c: fallos.append(n)
def run(app):
    for _ in range(40): app.update(); time.sleep(0.02)
    sw, sh, W, H = app.winfo_screenwidth(), app.winfo_screenheight(), app.winfo_width(), app.winfo_height()
    print(f"   pantalla {sw}x{sh} | ventana {W}x{H}")
    chk("la ventana entra en la pantalla", W <= sw and H <= sh, f"{W}x{H} en {sw}x{sh}")
    chk("RECUPERAR se ve completo", app.btn_go.winfo_height() >= app.btn_go.winfo_reqheight() - 1,
        f"{app.btn_go.winfo_height()} de {app.btn_go.winfo_reqheight()} px")
    chk("la tarjeta de destino se ve completa", app.fd.winfo_height() >= app.fd.winfo_reqheight() - 1,
        f"{app.fd.winfo_height()} de {app.fd.winfo_reqheight()} px")
    chk("el registro inferior se ve", app.txt.winfo_height() >= app.txt.winfo_reqheight() - 1,
        f"{app.txt.winfo_height()} de {app.txt.winfo_reqheight()} px")
    chk("el arbol conserva altura util (>= 120 px)", app.tree.winfo_height() >= 120, f"{app.tree.winfo_height()} px")
    chk("la barra de busqueda por nombre se ve", app.ent_name.winfo_ismapped() and app.ent_name.winfo_width() > 150)
    chk("las herramientas entran en el ancho", app.btn_tools.winfo_x() + app.btn_tools.winfo_width() < W)
    print("\nFALLOS: ninguno" if not fallos else f"\nFALLOS: {fallos}")
    app.destroy()
tkinter.Tk.mainloop = lambda self: run(self)
R.run_gui()
sys.exit(1 if fallos else 0)
