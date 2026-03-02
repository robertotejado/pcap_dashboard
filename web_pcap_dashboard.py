#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║         WIRESHARK PCAP VISUAL DASHBOARD              ║
║   Análisis gráfico de capturas de red en tiempo real ║
╚══════════════════════════════════════════════════════╝

Instalación:
    pip install scapy dash plotly pandas networkx dash-bootstrap-components

Uso:
    python pcap_dashboard.py                      → Demo con tráfico sintético
    python pcap_dashboard.py captura.pcap         → Analiza tu archivo .pcap
"""

import sys
import os
import random
import ipaddress
from collections import defaultdict, Counter
from datetime import datetime, timedelta

import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import dash
from dash import dcc, html, Input, Output, callback
import dash_bootstrap_components as dbc

# ──────────────────────────────────────────────
#  CARGA DEL PCAP (con Scapy) o datos demo
# ──────────────────────────────────────────────

def load_pcap(filepath):
    """Carga un archivo .pcap y extrae los campos relevantes."""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, ARP
        print(f"[+] Cargando {filepath}...")
        packets = rdpcap(filepath)
        rows = []
        start_ts = float(packets[0].time) if packets else 0

        for pkt in packets:
            ts = float(pkt.time) - start_ts
            proto = "OTHER"
            src_ip = dst_ip = src_port = dst_port = None
            size = len(pkt)

            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                if pkt.haslayer(TCP):
                    proto = "TCP"
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    if dst_port == 443 or src_port == 443:
                        proto = "HTTPS"
                    elif dst_port == 80 or src_port == 80:
                        proto = "HTTP"
                    elif dst_port == 22 or src_port == 22:
                        proto = "SSH"
                    elif dst_port == 21 or src_port == 21:
                        proto = "FTP"
                elif pkt.haslayer(UDP):
                    proto = "UDP"
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                    if dst_port == 53 or src_port == 53:
                        proto = "DNS"
                elif pkt.haslayer(ICMP):
                    proto = "ICMP"
            elif pkt.haslayer(ARP):
                proto = "ARP"
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst

            rows.append({
                "time": round(ts, 4),
                "src_ip": src_ip or "0.0.0.0",
                "dst_ip": dst_ip or "0.0.0.0",
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "size": size,
            })

        df = pd.DataFrame(rows)
        print(f"[+] Paquetes cargados: {len(df)}")
        return df

    except ImportError:
        print("[!] Scapy no instalado. Usando datos de DEMO.")
        return generate_demo_data()
    except Exception as e:
        print(f"[!] Error al leer pcap: {e}. Usando datos de DEMO.")
        return generate_demo_data()


def generate_demo_data(n=2000):
    """Genera tráfico de red sintético realista para demostración."""
    random.seed(42)
    protocols = ["HTTPS", "HTTP", "DNS", "TCP", "UDP", "SSH", "ICMP", "FTP", "ARP"]
    weights   = [0.30,   0.12,  0.18,  0.14, 0.10, 0.06, 0.05, 0.03, 0.02]

    ips_local  = [f"192.168.1.{i}" for i in range(1, 20)]
    ips_remote = [f"104.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(30)]
    all_ips = ips_local + ips_remote

    port_map = {"HTTPS": 443, "HTTP": 80, "DNS": 53, "SSH": 22, "FTP": 21,
                "TCP": random.randint(1024, 65535), "UDP": random.randint(1024, 65535),
                "ICMP": None, "ARP": None}

    rows = []
    t = 0.0
    for _ in range(n):
        t += random.expovariate(5)          # inter-arrival time
        proto = random.choices(protocols, weights=weights)[0]
        src = random.choice(ips_local)
        dst = random.choice(all_ips)
        sport = random.randint(1024, 65535)
        dport = port_map.get(proto) or random.randint(1, 1023)
        size  = int(random.lognormvariate(6, 1.2))
        rows.append({"time": round(t, 4), "src_ip": src, "dst_ip": dst,
                     "src_port": sport, "dst_port": dport,
                     "protocol": proto, "size": size})

    return pd.DataFrame(rows)


# ──────────────────────────────────────────────
#  PALETA Y ESTILOS
# ──────────────────────────────────────────────

PROTO_COLORS = {
    "HTTPS": "#00f5d4", "HTTP": "#fee440", "DNS": "#f15bb5",
    "TCP":   "#9b5de5", "UDP":  "#0077b6", "SSH": "#f77f00",
    "ICMP":  "#e63946", "FTP":  "#2dc653", "ARP": "#adb5bd",
    "OTHER": "#6c757d",
}

BG      = "#0a0e1a"
CARD_BG = "#111827"
BORDER  = "#1e2d45"
TEXT    = "#e2e8f0"
ACCENT  = "#00f5d4"

CARD_STYLE = {
    "backgroundColor": CARD_BG,
    "border": f"1px solid {BORDER}",
    "borderRadius": "12px",
    "padding": "18px",
    "marginBottom": "18px",
}

# ──────────────────────────────────────────────
#  FIGURAS PLOTLY
# ──────────────────────────────────────────────

def fig_timeline(df):
    """Tráfico a lo largo del tiempo (bytes por segundo)."""
    df2 = df.copy()
    df2["second"] = df2["time"].astype(int)
    ts = df2.groupby(["second", "protocol"])["size"].sum().reset_index()

    fig = go.Figure()
    for proto, grp in ts.groupby("protocol"):
        fig.add_trace(go.Scatter(
            x=grp["second"], y=grp["size"],
            mode="lines", stackgroup="one",
            name=proto, line=dict(width=0.5),
            fillcolor=PROTO_COLORS.get(proto, "#6c757d"),
            line_color=PROTO_COLORS.get(proto, "#6c757d"),
        ))
    fig.update_layout(**_layout("Tráfico en el tiempo (bytes/s)"))
    fig.update_xaxes(title_text="Tiempo (s)")
    fig.update_yaxes(title_text="Bytes")
    return fig


def fig_protocol_pie(df):
    proto_counts = df["protocol"].value_counts()
    colors = [PROTO_COLORS.get(p, "#6c757d") for p in proto_counts.index]
    fig = go.Figure(go.Pie(
        labels=proto_counts.index,
        values=proto_counts.values,
        hole=0.52,
        marker=dict(colors=colors, line=dict(color=BG, width=2)),
        textfont=dict(color=TEXT, size=12),
    ))
    fig.update_layout(**_layout("Distribución de Protocolos"))
    return fig


def fig_top_ips(df, n=15):
    src = df["src_ip"].value_counts().head(n).reset_index()
    src.columns = ["ip", "paquetes"]
    fig = go.Figure(go.Bar(
        x=src["paquetes"], y=src["ip"],
        orientation="h",
        marker=dict(
            color=src["paquetes"],
            colorscale=[[0, "#0d2137"], [0.5, "#9b5de5"], [1, ACCENT]],
            showscale=False,
        ),
        text=src["paquetes"], textposition="outside",
        textfont=dict(color=TEXT),
    ))
    fig.update_layout(**_layout(f"Top {n} IPs Origen"))
    fig.update_xaxes(showgrid=True, gridcolor=BORDER)
    fig.update_yaxes(autorange="reversed")
    return fig


def fig_packet_size_hist(df):
    fig = go.Figure(go.Histogram(
        x=df["size"],
        nbinsx=60,
        marker=dict(
            color=df["size"],
            colorscale=[[0, "#0d2137"], [0.5, "#f15bb5"], [1, ACCENT]],
            showscale=False,
        ),
        opacity=0.85,
    ))
    fig.update_layout(**_layout("Distribución del Tamaño de Paquetes"))
    fig.update_xaxes(title_text="Bytes")
    fig.update_yaxes(title_text="Frecuencia")
    return fig


def fig_connection_matrix(df, top_n=10):
    """Heatmap de conexiones entre IPs (top N)."""
    top_src = df["src_ip"].value_counts().head(top_n).index.tolist()
    top_dst = df["dst_ip"].value_counts().head(top_n).index.tolist()
    matrix = pd.DataFrame(0, index=top_src, columns=top_dst)
    sub = df[df["src_ip"].isin(top_src) & df["dst_ip"].isin(top_dst)]
    for _, row in sub.groupby(["src_ip", "dst_ip"]).size().reset_index(name="c").iterrows():
        if row["src_ip"] in matrix.index and row["dst_ip"] in matrix.columns:
            matrix.loc[row["src_ip"], row["dst_ip"]] = row["c"]

    fig = go.Figure(go.Heatmap(
        z=matrix.values,
        x=matrix.columns.tolist(),
        y=matrix.index.tolist(),
        colorscale=[[0, BG], [0.4, "#9b5de5"], [1, ACCENT]],
        showscale=True,
        hoverongaps=False,
    ))
    fig.update_layout(**_layout("Matriz de Conexiones (Top IPs)"))
    fig.update_xaxes(tickangle=30, tickfont=dict(size=10))
    return fig


def fig_network_graph(df, max_edges=120):
    """Grafo de red IP → IP usando NetworkX + Plotly."""
    try:
        import networkx as nx
    except ImportError:
        return go.Figure().add_annotation(
            text="pip install networkx para ver el grafo",
            showarrow=False, font=dict(color=TEXT, size=14),
            xref="paper", yref="paper", x=0.5, y=0.5
        )

    # Agregar conexiones
    conn = df.groupby(["src_ip", "dst_ip"]).agg(
        packets=("size", "count"), bytes=("size", "sum")
    ).reset_index().sort_values("packets", ascending=False).head(max_edges)

    G = nx.DiGraph()
    for _, r in conn.iterrows():
        G.add_edge(r["src_ip"], r["dst_ip"], weight=r["packets"])

    pos = nx.spring_layout(G, seed=42, k=2)

    edge_x, edge_y = [], []
    for u, v in G.edges():
        x0, y0 = pos[u]; x1, y1 = pos[v]
        edge_x += [x0, x1, None]; edge_y += [y0, y1, None]

    node_x = [pos[n][0] for n in G.nodes()]
    node_y = [pos[n][1] for n in G.nodes()]
    degree = [G.degree(n) for n in G.nodes()]
    labels = list(G.nodes())

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode="lines",
                             line=dict(width=0.6, color="#2a3f5f"), hoverinfo="none"))
    fig.add_trace(go.Scatter(
        x=node_x, y=node_y, mode="markers+text",
        marker=dict(size=[8 + d*2 for d in degree],
                    color=degree, colorscale="Viridis", showscale=True,
                    line=dict(width=1, color=BG)),
        text=labels, textposition="top center",
        textfont=dict(size=8, color=TEXT),
        hovertext=[f"{n}<br>Conexiones: {d}" for n, d in zip(labels, degree)],
        hoverinfo="text",
    ))
    fig.update_layout(**_layout("Grafo de Red (IP ↔ IP)"))
    fig.update_xaxes(visible=False); fig.update_yaxes(visible=False)
    return fig


def fig_top_ports(df, n=12):
    """Top puertos destino."""
    ports = df["dst_port"].dropna().astype(int).value_counts().head(n)
    port_names = {80: "HTTP", 443: "HTTPS", 22: "SSH", 53: "DNS",
                  21: "FTP", 25: "SMTP", 3306: "MySQL", 5432: "PG",
                  3389: "RDP", 8080: "HTTP-alt", 6379: "Redis"}
    labels = [f"{p} ({port_names.get(p, '')})" for p in ports.index]
    colors = [PROTO_COLORS.get(port_names.get(p, "OTHER"), "#6c757d") for p in ports.index]

    fig = go.Figure(go.Bar(
        x=labels, y=ports.values,
        marker=dict(color=colors, line=dict(color=BG, width=1)),
        text=ports.values, textposition="outside", textfont=dict(color=TEXT),
    ))
    fig.update_layout(**_layout(f"Top {n} Puertos Destino"))
    fig.update_xaxes(tickangle=25)
    return fig


def _layout(title):
    return dict(
        title=dict(text=title, font=dict(color=ACCENT, size=15, family="Courier New")),
        paper_bgcolor=CARD_BG,
        plot_bgcolor=CARD_BG,
        font=dict(color=TEXT, family="Courier New"),
        margin=dict(l=10, r=10, t=45, b=10),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=11)),
        hoverlabel=dict(bgcolor="#1e2d45", font_color=TEXT),
        xaxis=dict(gridcolor=BORDER, zerolinecolor=BORDER),
        yaxis=dict(gridcolor=BORDER, zerolinecolor=BORDER),
    )


# ──────────────────────────────────────────────
#  KPI CARDS
# ──────────────────────────────────────────────

def kpi_card(label, value, icon="📊", color=ACCENT):
    return html.Div([
        html.Div(icon, style={"fontSize": "28px"}),
        html.Div(str(value), style={
            "fontSize": "26px", "fontWeight": "700",
            "color": color, "fontFamily": "Courier New",
        }),
        html.Div(label, style={"fontSize": "12px", "color": "#94a3b8", "marginTop": "4px"}),
    ], style={**CARD_STYLE, "textAlign": "center", "minWidth": "160px"})


# ──────────────────────────────────────────────
#  DASH APP
# ──────────────────────────────────────────────

def build_app(df):
    app = dash.Dash(
        __name__,
        external_stylesheets=[dbc.themes.BOOTSTRAP],
        title="PCAP Dashboard"
    )

    # KPIs
    total_pkts   = len(df)
    total_bytes  = df["size"].sum()
    unique_src   = df["src_ip"].nunique()
    unique_dst   = df["dst_ip"].nunique()
    top_proto    = df["protocol"].value_counts().idxmax()
    duration     = round(df["time"].max(), 1)

    def human_bytes(n):
        for unit in ["B", "KB", "MB", "GB"]:
            if n < 1024: return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    app.layout = html.Div(style={"backgroundColor": BG, "minHeight": "100vh",
                                  "fontFamily": "Courier New, monospace", "padding": "24px"}, children=[

        # ── Header ──
        html.Div([
            html.Span("⬡ ", style={"color": ACCENT, "fontSize": "32px"}),
            html.Span("PCAP NETWORK DASHBOARD", style={
                "fontSize": "22px", "fontWeight": "700", "color": ACCENT,
                "letterSpacing": "4px", "verticalAlign": "middle",
            }),
            html.Span("  //  Network Traffic Analyzer", style={
                "color": "#4a5568", "fontSize": "13px", "marginLeft": "12px",
            }),
        ], style={"marginBottom": "24px", "borderBottom": f"1px solid {BORDER}", "paddingBottom": "16px"}),

        # ── KPI Row ──
        html.Div([
            kpi_card("Total Paquetes",  f"{total_pkts:,}",      "📦"),
            kpi_card("Total Bytes",      human_bytes(total_bytes),"💾", "#fee440"),
            kpi_card("IPs Origen",       unique_src,              "🖥️",  "#f15bb5"),
            kpi_card("IPs Destino",      unique_dst,              "🌐", "#9b5de5"),
            kpi_card("Proto Dominante",  top_proto,               "🔗", "#f77f00"),
            kpi_card("Duración (s)",     duration,                "⏱️",  "#2dc653"),
        ], style={"display": "flex", "gap": "14px", "flexWrap": "wrap", "marginBottom": "8px"}),

        # ── Fila 1: Timeline + Pie ──
        html.Div([
            html.Div(dcc.Graph(figure=fig_timeline(df),        config={"displayModeBar": False}),
                     style={**CARD_STYLE, "flex": "3"}),
            html.Div(dcc.Graph(figure=fig_protocol_pie(df),    config={"displayModeBar": False}),
                     style={**CARD_STYLE, "flex": "1.2"}),
        ], style={"display": "flex", "gap": "14px"}),

        # ── Fila 2: Top IPs + Tamaño de paquetes ──
        html.Div([
            html.Div(dcc.Graph(figure=fig_top_ips(df),         config={"displayModeBar": False}),
                     style={**CARD_STYLE, "flex": "1"}),
            html.Div(dcc.Graph(figure=fig_packet_size_hist(df), config={"displayModeBar": False}),
                     style={**CARD_STYLE, "flex": "1"}),
        ], style={"display": "flex", "gap": "14px"}),

        # ── Fila 3: Puertos + Matriz conexiones ──
        html.Div([
            html.Div(dcc.Graph(figure=fig_top_ports(df),        config={"displayModeBar": False}),
                     style={**CARD_STYLE, "flex": "1"}),
            html.Div(dcc.Graph(figure=fig_connection_matrix(df), config={"displayModeBar": False}),
                     style={**CARD_STYLE, "flex": "1.4"}),
        ], style={"display": "flex", "gap": "14px"}),

        # ── Fila 4: Grafo de red ──
        html.Div(dcc.Graph(figure=fig_network_graph(df), config={"displayModeBar": False},
                           style={"height": "520px"}),
                 style=CARD_STYLE),

        # ── Footer ──
        html.Div("⬡  PCAP Dashboard  //  Powered by Scapy + Plotly + Dash",
                 style={"textAlign": "center", "color": "#2d3748", "fontSize": "11px",
                        "paddingTop": "12px", "borderTop": f"1px solid {BORDER}"}),
    ])

    return app


# ──────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────

if __name__ == "__main__":
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else None

    if pcap_file:
        if not os.path.exists(pcap_file):
            print(f"[!] Archivo no encontrado: {pcap_file}")
            sys.exit(1)
        df = load_pcap(pcap_file)
    else:
        print("[*] Sin archivo .pcap → cargando datos de DEMO")
        print("[*] Uso: python pcap_dashboard.py mi_captura.pcap")
        df = generate_demo_data()

    print(f"[+] Iniciando dashboard → http://127.0.0.1:8050")
    app = build_app(df)
    app.run(debug=False, port=8050)
