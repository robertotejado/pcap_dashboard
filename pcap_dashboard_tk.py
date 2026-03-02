#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         WIRESHARK PCAP DASHBOARD  ·  Tkinter Edition         ║
║     Análisis gráfico de capturas de red — GUI Desktop        ║
╚══════════════════════════════════════════════════════════════╝

Instalación:
    pip install scapy matplotlib pandas networkx pillow

Uso:
    python pcap_dashboard_tk.py                → Demo sintético
    python pcap_dashboard_tk.py captura.pcap   → Tu archivo .pcap
    (También puedes abrir el .pcap desde el botón "📂 Abrir PCAP")
"""

import sys, os, random, threading, math
from collections import defaultdict, Counter
from tkinter import *
from tkinter import ttk, filedialog, messagebox
import tkinter as tk

import pandas as pd
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.colors import LinearSegmentedColormap
import matplotlib.gridspec as gridspec

# ─────────────────────────────────────────────
#  PALETA
# ─────────────────────────────────────────────
BG       = "#0a0e1a"
CARD     = "#111827"
BORDER   = "#1e2d45"
TEXT     = "#e2e8f0"
ACCENT   = "#00f5d4"
ACCENT2  = "#9b5de5"
YELLOW   = "#fee440"
PINK     = "#f15bb5"
ORANGE   = "#f77f00"
GREEN    = "#2dc653"
RED      = "#e63946"

PROTO_C = {
    "HTTPS": ACCENT,  "HTTP": YELLOW,  "DNS": PINK,
    "TCP":   ACCENT2, "UDP": "#0077b6","SSH": ORANGE,
    "ICMP":  RED,     "FTP": GREEN,    "ARP": "#adb5bd",
    "OTHER": "#6c757d",
}

plt.rcParams.update({
    "axes.facecolor":   CARD,
    "figure.facecolor": CARD,
    "axes.edgecolor":   BORDER,
    "axes.labelcolor":  TEXT,
    "xtick.color":      TEXT,
    "ytick.color":      TEXT,
    "text.color":       TEXT,
    "grid.color":       BORDER,
    "grid.linestyle":   "--",
    "grid.alpha":       0.4,
    "font.family":      "monospace",
    "axes.titlecolor":  ACCENT,
    "axes.titlesize":   10,
    "axes.titleweight": "bold",
})

# ─────────────────────────────────────────────
#  DATOS
# ─────────────────────────────────────────────

def load_pcap(filepath):
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP
        packets = rdpcap(filepath)
        rows = []
        start_ts = float(packets[0].time) if packets else 0
        for pkt in packets:
            ts    = float(pkt.time) - start_ts
            proto = "OTHER"
            src_ip = dst_ip = None
            src_port = dst_port = None
            size  = len(pkt)
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src; dst_ip = pkt[IP].dst
                if pkt.haslayer(TCP):
                    proto    = "TCP"
                    src_port = pkt[TCP].sport; dst_port = pkt[TCP].dport
                    if dst_port in (443,8443) or src_port in (443,8443): proto = "HTTPS"
                    elif dst_port in (80,8080) or src_port in (80,8080): proto = "HTTP"
                    elif 22 in (dst_port, src_port): proto = "SSH"
                    elif 21 in (dst_port, src_port): proto = "FTP"
                elif pkt.haslayer(UDP):
                    proto = "UDP"
                    src_port = pkt[UDP].sport; dst_port = pkt[UDP].dport
                    if 53 in (dst_port, src_port): proto = "DNS"
                elif pkt.haslayer(ICMP): proto = "ICMP"
            elif pkt.haslayer(ARP):
                proto  = "ARP"
                src_ip = pkt[ARP].psrc; dst_ip = pkt[ARP].pdst
            rows.append({"time": round(ts,4), "src_ip": src_ip or "0.0.0.0",
                         "dst_ip": dst_ip or "0.0.0.0",
                         "src_port": src_port, "dst_port": dst_port,
                         "protocol": proto, "size": size})
        return pd.DataFrame(rows)
    except ImportError:
        return generate_demo()
    except Exception as e:
        messagebox.showerror("Error PCAP", str(e))
        return generate_demo()


def generate_demo(n=2500):
    random.seed(99)
    protocols = ["HTTPS","HTTP","DNS","TCP","UDP","SSH","ICMP","FTP","ARP"]
    weights   = [0.30,  0.12, 0.18, 0.14,0.10, 0.06, 0.05, 0.03, 0.02]
    ips_local  = [f"192.168.1.{i}" for i in range(1, 25)]
    ips_remote = [f"104.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                  for _ in range(30)]
    all_ips = ips_local + ips_remote
    port_map = {"HTTPS":443,"HTTP":80,"DNS":53,"SSH":22,"FTP":21}
    rows=[]; t=0.0
    for _ in range(n):
        t += random.expovariate(6)
        proto = random.choices(protocols, weights=weights)[0]
        src   = random.choice(ips_local)
        dst   = random.choice(all_ips)
        sport = random.randint(1024,65535)
        dport = port_map.get(proto, random.randint(1,1023))
        size  = max(40, int(random.lognormvariate(6,1.3)))
        rows.append({"time":round(t,4),"src_ip":src,"dst_ip":dst,
                     "src_port":sport,"dst_port":dport,"protocol":proto,"size":size})
    return pd.DataFrame(rows)


def human_bytes(n):
    for u in ["B","KB","MB","GB"]:
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"

# ─────────────────────────────────────────────
#  PLOTS
# ─────────────────────────────────────────────

def plot_timeline(ax, df):
    df2 = df.copy(); df2["second"] = df2["time"].astype(int)
    ts  = df2.groupby(["second","protocol"])["size"].sum().unstack(fill_value=0)
    protos = [p for p in PROTO_C if p in ts.columns]
    colors = [PROTO_C[p] for p in protos]
    ax.stackplot(ts.index, [ts[p] for p in protos], labels=protos,
                 colors=colors, alpha=0.85)
    ax.set_title("Tráfico en el Tiempo  (bytes/s)")
    ax.set_xlabel("Tiempo (s)"); ax.set_ylabel("Bytes")
    ax.legend(loc="upper right", fontsize=7, framealpha=0.3,
              ncol=2, labelcolor=TEXT)
    ax.grid(True)


def plot_pie(ax, df):
    vc = df["protocol"].value_counts()
    colors = [PROTO_C.get(p,"#6c757d") for p in vc.index]
    wedges, texts, autotexts = ax.pie(
        vc.values, labels=vc.index, colors=colors,
        autopct="%1.1f%%", startangle=140,
        pctdistance=0.78,
        wedgeprops=dict(width=0.55, edgecolor=BG, linewidth=1.5),
    )
    for t in texts:    t.set_color(TEXT); t.set_fontsize(8)
    for a in autotexts: a.set_color(BG);  a.set_fontsize(7); a.set_fontweight("bold")
    ax.set_title("Protocolos")


def plot_top_ips(ax, df, n=12):
    vc = df["src_ip"].value_counts().head(n)
    cmap = LinearSegmentedColormap.from_list("c",[BORDER, ACCENT2, ACCENT])
    norm_vals = [v/vc.max() for v in vc.values]
    colors = [cmap(v) for v in norm_vals]
    bars = ax.barh(range(len(vc)), vc.values, color=colors, edgecolor=BG, linewidth=0.5)
    ax.set_yticks(range(len(vc))); ax.set_yticklabels(vc.index, fontsize=7)
    ax.invert_yaxis()
    ax.set_title(f"Top {n} IPs Origen")
    ax.set_xlabel("Paquetes"); ax.grid(True, axis="x")
    for bar, val in zip(bars, vc.values):
        ax.text(bar.get_width()+0.5, bar.get_y()+bar.get_height()/2,
                str(val), va="center", fontsize=7, color=ACCENT)


def plot_hist(ax, df):
    cmap = LinearSegmentedColormap.from_list("h",[BORDER, PINK, ACCENT])
    n, bins, patches = ax.hist(df["size"].clip(upper=2000), bins=60,
                                edgecolor=BG, linewidth=0.3)
    for i, patch in enumerate(patches):
        patch.set_facecolor(cmap(i/len(patches)))
    ax.set_title("Distribución Tamaño de Paquetes")
    ax.set_xlabel("Bytes"); ax.set_ylabel("Frecuencia"); ax.grid(True, axis="y")


def plot_ports(ax, df, n=10):
    port_names = {80:"HTTP",443:"HTTPS",22:"SSH",53:"DNS",21:"FTP",
                  25:"SMTP",3306:"MySQL",5432:"PG",3389:"RDP",8080:"HTTP-alt",
                  6379:"Redis",27017:"Mongo"}
    vc = df["dst_port"].dropna().astype(int).value_counts().head(n)
    labels = [f"{p}\n{port_names.get(p,'')}" for p in vc.index]
    colors = [PROTO_C.get(port_names.get(p,"OTHER"),"#6c757d") for p in vc.index]
    bars = ax.bar(range(len(vc)), vc.values, color=colors, edgecolor=BG, linewidth=0.5)
    ax.set_xticks(range(len(vc))); ax.set_xticklabels(labels, fontsize=7)
    ax.set_title(f"Top {n} Puertos Destino")
    ax.set_ylabel("Paquetes"); ax.grid(True, axis="y")
    for bar, val in zip(bars, vc.values):
        ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.5,
                str(val), ha="center", fontsize=7, color=TEXT)


def plot_heatmap(ax, df, top_n=8):
    top_src = df["src_ip"].value_counts().head(top_n).index.tolist()
    top_dst = df["dst_ip"].value_counts().head(top_n).index.tolist()
    matrix  = pd.DataFrame(0, index=top_src, columns=top_dst)
    sub = df[df["src_ip"].isin(top_src) & df["dst_ip"].isin(top_dst)]
    for _, r in sub.groupby(["src_ip","dst_ip"]).size().reset_index(name="c").iterrows():
        if r["src_ip"] in matrix.index and r["dst_ip"] in matrix.columns:
            matrix.loc[r["src_ip"], r["dst_ip"]] = r["c"]
    cmap = LinearSegmentedColormap.from_list("m",[BG, ACCENT2, ACCENT])
    im   = ax.imshow(matrix.values, cmap=cmap, aspect="auto")
    ax.set_xticks(range(len(top_dst))); ax.set_xticklabels(top_dst, rotation=30, fontsize=6)
    ax.set_yticks(range(len(top_src))); ax.set_yticklabels(top_src, fontsize=6)
    plt.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    ax.set_title("Matriz Conexiones (Top IPs)")
    for i in range(len(top_src)):
        for j in range(len(top_dst)):
            v = matrix.iloc[i,j]
            if v > 0:
                ax.text(j, i, str(v), ha="center", va="center",
                        fontsize=6, color=BG if v > matrix.values.max()*0.5 else TEXT)


def plot_network(ax, df, max_edges=80):
    try:
        import networkx as nx
    except ImportError:
        ax.text(0.5, 0.5, "pip install networkx\npara ver el grafo",
                ha="center", va="center", color=ACCENT, transform=ax.transAxes, fontsize=10)
        ax.set_title("Grafo de Red"); return

    conn = (df.groupby(["src_ip","dst_ip"])
              .agg(pkts=("size","count"), bts=("size","sum"))
              .reset_index()
              .sort_values("pkts", ascending=False)
              .head(max_edges))

    G = nx.DiGraph()
    for _, r in conn.iterrows():
        G.add_edge(r["src_ip"], r["dst_ip"], weight=r["pkts"])

    pos    = nx.spring_layout(G, seed=7, k=1.8)
    degree = dict(G.degree())
    sizes  = [120 + degree[n]*40 for n in G.nodes()]
    colors = [degree[n] for n in G.nodes()]

    nx.draw_networkx_edges(G, pos, ax=ax, alpha=0.25,
                           edge_color=BORDER, arrows=True,
                           arrowsize=8, width=0.7)
    sc = nx.draw_networkx_nodes(G, pos, ax=ax,
                                node_size=sizes, node_color=colors,
                                cmap=plt.cm.plasma, alpha=0.9)
    nx.draw_networkx_labels(G, pos, ax=ax, font_size=5,
                            font_color=TEXT, font_family="monospace")
    plt.colorbar(sc, ax=ax, fraction=0.02, pad=0.01, label="Conexiones")
    ax.set_title("Grafo de Red  (IP ↔ IP)")
    ax.axis("off")


def plot_proto_time(ax, df):
    """Protocolo más activo por ventana de tiempo."""
    df2 = df.copy(); df2["second"] = df2["time"].astype(int)
    ts  = df2.groupby(["second","protocol"])["size"].count().unstack(fill_value=0)
    for proto in [p for p in PROTO_C if p in ts.columns]:
        ax.plot(ts.index, ts[proto], label=proto,
                color=PROTO_C[proto], linewidth=1.2, alpha=0.85)
    ax.set_title("Paquetes/s por Protocolo")
    ax.set_xlabel("Tiempo (s)"); ax.set_ylabel("Paquetes")
    ax.legend(fontsize=6, framealpha=0.2, ncol=3, labelcolor=TEXT)
    ax.grid(True)


# ─────────────────────────────────────────────
#  APP TKINTER
# ─────────────────────────────────────────────

class PCAPDashboard(tk.Tk):
    def __init__(self, initial_file=None):
        super().__init__()
        self.title("⬡  PCAP Network Dashboard")
        self.configure(bg=BG)
        self.geometry("1400x900")
        self.minsize(1100, 750)

        self.df = None
        self._build_ui()
        self._apply_style()

        if initial_file:
            self.after(200, lambda: self._load_file(initial_file))
        else:
            self.after(200, self._load_demo)

    # ── UI STRUCTURE ──────────────────────────

    def _build_ui(self):
        # ── Top bar ──
        top = tk.Frame(self, bg=BG, pady=10, padx=16)
        top.pack(fill=X)

        tk.Label(top, text="⬡  PCAP NETWORK DASHBOARD",
                 bg=BG, fg=ACCENT,
                 font=("Courier New", 16, "bold"),
                 padx=0).pack(side=LEFT)
        tk.Label(top, text="  //  Wireshark PCAP Analyzer",
                 bg=BG, fg="#4a5568",
                 font=("Courier New", 10)).pack(side=LEFT)

        # Buttons
        btn_frame = tk.Frame(top, bg=BG)
        btn_frame.pack(side=RIGHT)
        self._make_btn(btn_frame, "📂  Abrir PCAP",  self._open_file,  ACCENT).pack(side=LEFT, padx=4)
        self._make_btn(btn_frame, "🎲  Demo",        self._load_demo,  ACCENT2).pack(side=LEFT, padx=4)
        self._make_btn(btn_frame, "🔄  Actualizar",  self._refresh,    YELLOW).pack(side=LEFT, padx=4)

        # ── Separator ──
        tk.Frame(self, bg=BORDER, height=1).pack(fill=X)

        # ── KPI strip ──
        self.kpi_frame = tk.Frame(self, bg=BG, pady=10, padx=12)
        self.kpi_frame.pack(fill=X)

        # ── Status bar ──
        self.status_var = tk.StringVar(value="Listo")
        status = tk.Label(self, textvariable=self.status_var, bg=BORDER,
                          fg=TEXT, anchor=W, padx=8,
                          font=("Courier New", 9))
        status.pack(side=BOTTOM, fill=X)

        # ── Tab notebook ──
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill=BOTH, expand=True, padx=10, pady=(4,2))

        self.tabs = {}
        tab_defs = [
            ("📈 Tráfico",     "traffic"),
            ("🥧 Protocolos",  "proto"),
            ("🖥️  IPs",         "ips"),
            ("🔌 Puertos",     "ports"),
            ("🔥 Conexiones",  "conn"),
            ("🕸️  Grafo",       "graph"),
        ]
        for label, key in tab_defs:
            frame = tk.Frame(self.nb, bg=CARD)
            self.nb.add(frame, text=label)
            self.tabs[key] = frame

    def _make_btn(self, parent, text, cmd, color):
        return tk.Button(parent, text=text, command=cmd,
                         bg=CARD, fg=color,
                         activebackground=BORDER, activeforeground=color,
                         relief=FLAT, bd=0, padx=12, pady=6,
                         font=("Courier New", 9, "bold"),
                         cursor="hand2",
                         highlightthickness=1, highlightbackground=color)

    def _apply_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook",        background=BG,    borderwidth=0)
        style.configure("TNotebook.Tab",    background=CARD,  foreground=TEXT,
                                            padding=[14,6],   font=("Courier New",9))
        style.map("TNotebook.Tab",
                  background=[("selected", BORDER)],
                  foreground=[("selected", ACCENT)])

    # ── KPI CARDS ─────────────────────────────

    def _refresh_kpis(self):
        for w in self.kpi_frame.winfo_children():
            w.destroy()

        df = self.df
        kpis = [
            ("📦", f"{len(df):,}",               "Total Paquetes", ACCENT),
            ("💾", human_bytes(df['size'].sum()), "Total Bytes",    YELLOW),
            ("🖥️",  str(df['src_ip'].nunique()),   "IPs Origen",     PINK),
            ("🌐", str(df['dst_ip'].nunique()),   "IPs Destino",    ACCENT2),
            ("🔗", df['protocol'].value_counts().idxmax(), "Protocolo Top", ORANGE),
            ("⏱️",  f"{df['time'].max():.1f} s",  "Duración",       GREEN),
            ("📊", str(df['protocol'].nunique()), "Protocolos",     RED),
        ]
        for icon, val, label, color in kpis:
            card = tk.Frame(self.kpi_frame, bg=CARD,
                            highlightthickness=1, highlightbackground=BORDER,
                            padx=16, pady=8)
            card.pack(side=LEFT, padx=6)
            tk.Label(card, text=icon,  bg=CARD, fg=color,
                     font=("Courier New", 20)).pack()
            tk.Label(card, text=val,   bg=CARD, fg=color,
                     font=("Courier New", 14, "bold")).pack()
            tk.Label(card, text=label, bg=CARD, fg="#64748b",
                     font=("Courier New", 8)).pack()

    # ── CHARTS ────────────────────────────────

    def _clear_tab(self, key):
        for w in self.tabs[key].winfo_children():
            w.destroy()

    def _embed(self, fig, tab_key):
        canvas = FigureCanvasTkAgg(fig, master=self.tabs[tab_key])
        canvas.draw()
        canvas.get_tk_widget().pack(fill=BOTH, expand=True)
        return canvas

    def _draw_all(self):
        df = self.df
        self._refresh_kpis()

        # ── Tab: Tráfico ──
        self._clear_tab("traffic")
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(13, 6),
                                        facecolor=CARD, tight_layout=True)
        plot_timeline(ax1, df)
        plot_proto_time(ax2, df)
        self._embed(fig, "traffic")

        # ── Tab: Protocolos ──
        self._clear_tab("proto")
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5),
                                        facecolor=CARD, tight_layout=True)
        plot_pie(ax1, df)
        plot_hist(ax2, df)
        self._embed(fig, "proto")

        # ── Tab: IPs ──
        self._clear_tab("ips")
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5),
                                        facecolor=CARD, tight_layout=True)
        plot_top_ips(ax1, df, n=15)
        # Top IPs destino
        vc = df["dst_ip"].value_counts().head(15)
        cmap2 = LinearSegmentedColormap.from_list("c2",[BORDER, PINK, YELLOW])
        bars = ax2.barh(range(len(vc)), vc.values,
                        color=[cmap2(v/vc.max()) for v in vc.values], edgecolor=BG)
        ax2.set_yticks(range(len(vc))); ax2.set_yticklabels(vc.index, fontsize=7)
        ax2.invert_yaxis(); ax2.set_title("Top 15 IPs Destino")
        ax2.set_xlabel("Paquetes"); ax2.grid(True, axis="x")
        self._embed(fig, "ips")

        # ── Tab: Puertos ──
        self._clear_tab("ports")
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5),
                                        facecolor=CARD, tight_layout=True)
        plot_ports(ax1, df, n=12)
        # Puertos origen
        vc2 = df["src_port"].dropna().astype(int).value_counts().head(12)
        ax2.bar(range(len(vc2)), vc2.values, color=ACCENT2,
                edgecolor=BG, linewidth=0.5, alpha=0.8)
        ax2.set_xticks(range(len(vc2))); ax2.set_xticklabels(vc2.index, fontsize=7)
        ax2.set_title("Top 12 Puertos Origen"); ax2.set_ylabel("Paquetes")
        ax2.grid(True, axis="y")
        self._embed(fig, "ports")

        # ── Tab: Conexiones ──
        self._clear_tab("conn")
        fig, ax = plt.subplots(figsize=(13, 5.5), facecolor=CARD, tight_layout=True)
        plot_heatmap(ax, df, top_n=10)
        self._embed(fig, "conn")

        # ── Tab: Grafo ──
        self._clear_tab("graph")
        fig, ax = plt.subplots(figsize=(13, 6), facecolor=CARD, tight_layout=True)
        plot_network(ax, df, max_edges=100)
        self._embed(fig, "graph")

        plt.close("all")

    # ── LOADERS ───────────────────────────────

    def _load_demo(self):
        self.status_var.set("⏳  Generando datos de demo...")
        self.update_idletasks()
        self.df = generate_demo()
        self.status_var.set(f"✅  Demo cargado  ·  {len(self.df):,} paquetes")
        self._draw_all()

    def _load_file(self, path):
        self.status_var.set(f"⏳  Cargando {os.path.basename(path)} …")
        self.update_idletasks()
        self.df = load_pcap(path)
        self.status_var.set(
            f"✅  {os.path.basename(path)}  ·  {len(self.df):,} paquetes")
        self._draw_all()

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="Seleccionar archivo PCAP",
            filetypes=[("PCAP files", "*.pcap *.pcapng *.cap"), ("All", "*.*")])
        if path:
            self._load_file(path)

    def _refresh(self):
        if self.df is not None:
            self._draw_all()


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else None
    if pcap_file and not os.path.exists(pcap_file):
        print(f"[!] Archivo no encontrado: {pcap_file}")
        sys.exit(1)
    app = PCAPDashboard(initial_file=pcap_file)
    app.mainloop()
