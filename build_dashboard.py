import json
import os

# Load JSON results
core_data = json.load(open('semgrep/out/core.json', encoding='utf-8'))['results']
admin_data = json.load(open('semgrep/out/admin.json', encoding='utf-8'))['results']
soap_data = json.load(open('semgrep/out/soap.json', encoding='utf-8'))['results']
summary = json.load(open('semgrep/summary.json', encoding='utf-8'))

all_findings = []
for r in core_data:
    r['_project'] = 'Core bWAPP'
    all_findings.append(r)
for r in admin_data:
    r['_project'] = 'admin'
    all_findings.append(r)
for r in soap_data:
    r['_project'] = 'soap (NuSOAP)'
    all_findings.append(r)

# Clean dataset for frontend
clean_findings = []
for idx, f in enumerate(all_findings):
    md = f.get('extra', {}).get('metadata', {})
    sev_raw = f.get('extra', {}).get('severity', 'WARNING')
    sev_map = {"ERROR": "Alta", "WARNING": "Media", "INFO": "Baja"}
    sev = sev_map.get(sev_raw, "Media")
    
    clean_findings.append({
        "id": idx + 1,
        "project": f['_project'],
        "check_id": f.get('check_id', ''),
        "rule_short": f.get('check_id', '').split('.')[-1],
        "category": md.get('category', f.get('check_id', '').split('.')[-1]),
        "severity": sev,
        "severity_raw": sev_raw,
        "owasp": md.get('owasp', 'OWASP no asignado'),
        "cwe": md.get('cwe', 'CWE no asignado'),
        "path": f.get('path', '').replace('\\', '/'),
        "file": os.path.basename(f.get('path', '')),
        "line_start": f.get('start', {}).get('line', 0),
        "line_end": f.get('end', {}).get('line', 0),
        "message": f.get('extra', {}).get('message', ''),
        "lines": f.get('extra', {}).get('lines', '').strip()
    })

findings_json_str = json.dumps(clean_findings, ensure_ascii=False)

html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auditoría SAST Semgrep — Análisis bWAPP | UMG</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <!-- Lucide Icons -->
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        :root {{
            --bg-page: #f8fafc;
            --bg-surface: #ffffff;
            --bg-subtle: #f1f5f9;
            --border-subtle: #e2e8f0;
            --border-strong: #cbd5e1;
            
            --text-heading: #0f172a;
            --text-body: #334155;
            --text-secondary: #64748b;
            --text-muted: #94a3b8;
            
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --primary-light: #eff6ff;
            --primary-border: #bfdbfe;
            
            --color-alta: #dc2626;
            --color-alta-bg: #fef2f2;
            --color-alta-border: #fecaca;
            
            --color-media: #d97706;
            --color-media-bg: #fffbeb;
            --color-media-border: #fde68a;
            
            --color-baja: #2563eb;
            --color-baja-bg: #eff6ff;
            --color-baja-border: #bfdbfe;
            
            --color-success: #16a34a;
            --color-success-bg: #f0fdf4;
            --color-success-border: #bbf7d0;

            --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.07), 0 2px 4px -2px rgba(0, 0, 0, 0.05);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.08), 0 4px 6px -4px rgba(0, 0, 0, 0.04);
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-page);
            color: var(--text-body);
            font-family: var(--font-sans);
            line-height: 1.5;
            min-height: 100vh;
        }}
        
        /* Header */
        header {{
            background: var(--bg-surface);
            border-bottom: 1px solid var(--border-subtle);
            padding: 1.25rem 2rem;
            position: sticky;
            top: 0;
            z-index: 50;
            box-shadow: var(--shadow-sm);
        }}
        .header-container {{
            max-width: 1440px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1.25rem;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        .brand-icon-wrap {{
            width: 44px;
            height: 44px;
            border-radius: 10px;
            background: var(--primary-light);
            border: 1px solid var(--primary-border);
            color: var(--primary);
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .brand-text h1 {{
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--text-heading);
            letter-spacing: -0.01em;
        }}
        .brand-meta {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-top: 0.15rem;
        }}
        .badge-pill {{
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            letter-spacing: 0.04em;
            background: var(--bg-subtle);
            color: var(--text-secondary);
            border: 1px solid var(--border-subtle);
        }}

        /* Navigation */
        .nav-tabs {{
            display: flex;
            background: var(--bg-subtle);
            padding: 0.3rem;
            border-radius: 10px;
            border: 1px solid var(--border-subtle);
            gap: 0.35rem;
            overflow-x: auto;
        }}
        .nav-tab {{
            background: transparent;
            border: none;
            color: var(--text-secondary);
            padding: 0.55rem 0.95rem;
            border-radius: 7px;
            font-weight: 600;
            font-size: 0.825rem;
            cursor: pointer;
            transition: all 0.15s ease;
            display: flex;
            align-items: center;
            gap: 0.45rem;
            white-space: nowrap;
        }}
        .nav-tab:hover {{
            color: var(--text-heading);
            background: rgba(255, 255, 255, 0.6);
        }}
        .nav-tab.active {{
            background: var(--bg-surface);
            color: var(--primary);
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--border-subtle);
        }}
        .nav-tab svg {{
            width: 16px;
            height: 16px;
        }}

        /* Layout */
        main {{
            max-width: 1440px;
            margin: 0 auto;
            padding: 2rem;
        }}
        .tab-panel {{ display: none; }}
        .tab-panel.active {{ display: block; animation: fadeIn 0.2s ease-out; }}
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(4px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        /* Metrics */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2rem;
        }}
        .metric-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            padding: 1.25rem 1.5rem;
            position: relative;
            box-shadow: var(--shadow-sm);
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }}
        .metric-card:hover {{
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }}
        .metric-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.6rem;
        }}
        .metric-title {{
            font-size: 0.775rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
        }}
        .metric-icon {{
            width: 32px;
            height: 32px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .metric-val {{
            font-size: 2.1rem;
            font-weight: 800;
            color: var(--text-heading);
            line-height: 1.1;
        }}
        .metric-sub {{
            font-size: 0.775rem;
            color: var(--text-muted);
            margin-top: 0.35rem;
        }}

        /* Projects Section */
        .projects-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        .project-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: var(--shadow-sm);
        }}
        .project-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }}
        .project-name {{
            font-size: 1.1rem;
            font-weight: 700;
            color: var(--text-heading);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .status-pill {{
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            padding: 0.25rem 0.7rem;
            border-radius: 9999px;
            font-size: 0.725rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }}
        .status-critica {{
            background: var(--color-alta-bg);
            color: var(--color-alta);
            border: 1px solid var(--color-alta-border);
        }}
        .status-alta {{
            background: var(--color-media-bg);
            color: var(--color-media);
            border: 1px solid var(--color-media-border);
        }}
        .status-media {{
            background: var(--color-baja-bg);
            color: var(--color-baja);
            border: 1px solid var(--color-baja-border);
        }}

        .findings-bar {{
            height: 8px;
            background: var(--bg-subtle);
            border-radius: 4px;
            overflow: hidden;
            display: flex;
            margin: 1rem 0 0.75rem;
        }}
        .bar-alta {{ background: var(--color-alta); }}
        .bar-media {{ background: var(--color-media); }}
        .bar-baja {{ background: var(--color-baja); }}

        /* Charts */
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(460px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        .chart-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: var(--shadow-sm);
        }}
        .chart-card h3 {{
            font-size: 0.95rem;
            font-weight: 700;
            color: var(--text-heading);
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .chart-img-wrap {{
            background: #ffffff;
            border: 1px solid var(--border-subtle);
            border-radius: 8px;
            padding: 0.5rem;
            display: flex;
            justify-content: center;
            align-items: center;
        }}
        .chart-img-wrap img {{
            max-width: 100%;
            height: auto;
            border-radius: 4px;
        }}

        /* Table & Controls */
        .controls-bar {{
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            padding: 1rem 1.25rem;
            margin-bottom: 1.25rem;
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            align-items: center;
            justify-content: space-between;
            box-shadow: var(--shadow-sm);
        }}
        .search-box {{
            flex: 1;
            min-width: 280px;
            position: relative;
        }}
        .search-box input {{
            width: 100%;
            background: var(--bg-subtle);
            border: 1px solid var(--border-subtle);
            border-radius: 8px;
            padding: 0.6rem 0.85rem 0.6rem 2.25rem;
            color: var(--text-heading);
            font-family: inherit;
            font-size: 0.85rem;
            transition: all 0.15s;
        }}
        .search-box input:focus {{
            outline: none;
            background: var(--bg-surface);
            border-color: var(--primary);
            box-shadow: 0 0 0 3px var(--primary-light);
        }}
        .search-icon-pos {{
            position: absolute;
            left: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            pointer-events: none;
            width: 16px;
            height: 16px;
        }}
        .filter-select {{
            background: var(--bg-subtle);
            border: 1px solid var(--border-subtle);
            color: var(--text-heading);
            padding: 0.6rem 0.85rem;
            border-radius: 8px;
            font-family: inherit;
            font-size: 0.85rem;
            font-weight: 500;
            cursor: pointer;
        }}
        .filter-select:focus {{
            outline: none;
            border-color: var(--primary);
        }}
        .table-wrap {{
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            overflow-x: auto;
            box-shadow: var(--shadow-sm);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            text-align: left;
        }}
        th {{
            background: var(--bg-subtle);
            color: var(--text-secondary);
            font-weight: 600;
            padding: 0.85rem 1rem;
            border-bottom: 1px solid var(--border-subtle);
            text-transform: uppercase;
            font-size: 0.7rem;
            letter-spacing: 0.05em;
        }}
        td {{
            padding: 0.85rem 1rem;
            border-bottom: 1px solid var(--border-subtle);
            vertical-align: middle;
            color: var(--text-body);
        }}
        tr:hover td {{
            background: var(--bg-subtle);
        }}
        .code-pill {{
            font-family: var(--font-mono);
            background: var(--bg-subtle);
            border: 1px solid var(--border-subtle);
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-size: 0.75rem;
            color: var(--primary);
            font-weight: 500;
        }}
        .sev-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
            padding: 0.2rem 0.55rem;
            border-radius: 6px;
            font-size: 0.725rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .sev-Alta {{
            background: var(--color-alta-bg);
            color: var(--color-alta);
            border: 1px solid var(--color-alta-border);
        }}
        .sev-Media {{
            background: var(--color-media-bg);
            color: var(--color-media);
            border: 1px solid var(--color-media-border);
        }}
        .sev-Baja {{
            background: var(--color-baja-bg);
            color: var(--color-baja);
            border: 1px solid var(--color-baja-border);
        }}

        /* Code Comparison Cards */
        .vuln-case-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: var(--shadow-sm);
        }}
        .vuln-case-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 0.75rem;
            margin-bottom: 0.75rem;
            border-bottom: 1px solid var(--border-subtle);
            padding-bottom: 0.75rem;
        }}
        .vuln-title {{
            font-size: 1.1rem;
            font-weight: 700;
            color: var(--text-heading);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .code-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin-top: 1rem;
        }}
        @media (max-width: 900px) {{
            .code-grid {{ grid-template-columns: 1fr; }}
        }}
        .code-block {{
            background: #0f172a;
            border-radius: 8px;
            overflow: hidden;
            font-family: var(--font-mono);
            font-size: 0.8rem;
            box-shadow: var(--shadow-sm);
        }}
        .code-header {{
            padding: 0.5rem 0.85rem;
            font-size: 0.725rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .code-header.vuln {{ background: #7f1d1d; color: #fecaca; }}
        .code-header.fix {{ background: #064e3b; color: #a7f3d0; }}
        pre {{
            padding: 1rem;
            overflow-x: auto;
            color: #f8fafc;
            line-height: 1.5;
        }}

        /* Presentation */
        .presentation-container {{
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 2.5rem;
            max-width: 1040px;
            margin: 0 auto;
            box-shadow: var(--shadow-md);
        }}
        .slide {{ display: none; }}
        .slide.active {{ display: block; animation: fadeIn 0.2s ease-out; }}
        .slide-tag {{
            color: var(--primary);
            font-size: 0.775rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }}
        .slide-title {{
            font-size: 1.75rem;
            font-weight: 800;
            color: var(--text-heading);
            margin-bottom: 1.5rem;
            letter-spacing: -0.01em;
        }}
        .slide-body {{
            font-size: 1rem;
            color: var(--text-body);
            line-height: 1.7;
        }}
        .slide-body ul {{
            padding-left: 1.5rem;
            margin: 1rem 0;
        }}
        .slide-body li {{
            margin-bottom: 0.75rem;
        }}
        .slide-controls {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 2.5rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-subtle);
        }}
        .btn {{
            background: var(--primary);
            color: #ffffff;
            border: none;
            padding: 0.6rem 1.4rem;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.15s;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .btn:hover {{ background: var(--primary-hover); transform: translateY(-1px); }}
        .btn-secondary {{
            background: var(--bg-subtle);
            border: 1px solid var(--border-subtle);
            color: var(--text-body);
        }}
        .btn-secondary:hover {{ background: #e2e8f0; color: var(--text-heading); }}
    </style>
</head>
<body>

<header>
    <div class="header-container">
        <div class="brand">
            <div class="brand-icon-wrap">
                <i data-lucide="shield-check"></i>
            </div>
            <div class="brand-text">
                <h1>Auditoría SAST Semgrep — bWAPP</h1>
                <div class="brand-meta">
                    <span class="badge-pill">Universidad Mariano Gálvez</span>
                    <span>Seguridad de Aplicaciones</span>
                    <span>Estudiante: Josias Suhul</span>
                </div>
            </div>
        </div>
        <nav class="nav-tabs">
            <button class="nav-tab active" onclick="switchTab('dashboard')">
                <i data-lucide="layout-dashboard"></i> Dashboard & Postura
            </button>
            <button class="nav-tab" onclick="switchTab('graficas')">
                <i data-lucide="bar-chart-3"></i> Gráficas Oficiales
            </button>
            <button class="nav-tab" onclick="switchTab('hallazgos')">
                <i data-lucide="file-search"></i> Explorador de Hallazgos
            </button>
            <button class="nav-tab" onclick="switchTab('casos')">
                <i data-lucide="shield-alert"></i> 5 Casos & Remediación
            </button>
            <button class="nav-tab" onclick="switchTab('triaje')">
                <i data-lucide="scale"></i> Triaje Falso Positivo
            </button>
            <button class="nav-tab" onclick="switchTab('exposicion')">
                <i data-lucide="presentation"></i> Modo Exposición
            </button>
        </nav>
    </div>
</header>

<main>
    <!-- TAB 1: DASHBOARD & POSTURA -->
    <div id="tab-dashboard" class="tab-panel active">
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-top">
                    <span class="metric-title">Hallazgos Totales</span>
                    <div class="metric-icon" style="background:#eff6ff; color:#2563eb;"><i data-lucide="list-filter"></i></div>
                </div>
                <div class="metric-val">138</div>
                <div class="metric-sub">Sobre 198 archivos auditados</div>
            </div>
            <div class="metric-card">
                <div class="metric-top">
                    <span class="metric-title">Índice Ponderado</span>
                    <div class="metric-icon" style="background:#f5f3ff; color:#7c3aed;"><i data-lucide="gauge"></i></div>
                </div>
                <div class="metric-val">538</div>
                <div class="metric-sub">(Alta×5) + (Media×3) + (Baja×1)</div>
            </div>
            <div class="metric-card">
                <div class="metric-top">
                    <span class="metric-title">Severidad Alta (Error)</span>
                    <div class="metric-icon" style="background:var(--color-alta-bg); color:var(--color-alta);"><i data-lucide="alert-triangle"></i></div>
                </div>
                <div class="metric-val" style="color:var(--color-alta);">66</div>
                <div class="metric-sub">48% del total (SQLi, RCE, LFI)</div>
            </div>
            <div class="metric-card">
                <div class="metric-top">
                    <span class="metric-title">Severidad Media (Warning)</span>
                    <div class="metric-icon" style="background:var(--color-media-bg); color:var(--color-media);"><i data-lucide="alert-circle"></i></div>
                </div>
                <div class="metric-val" style="color:var(--color-media);">68</div>
                <div class="metric-sub">49% del total (XSS, Open Redirect)</div>
            </div>
            <div class="metric-card">
                <div class="metric-top">
                    <span class="metric-title">Severidad Baja (Info)</span>
                    <div class="metric-icon" style="background:var(--color-baja-bg); color:var(--color-baja);"><i data-lucide="info"></i></div>
                </div>
                <div class="metric-val" style="color:var(--color-baja);">4</div>
                <div class="metric-sub">3% del total (Divulgación técnica)</div>
            </div>
        </div>

        <h2 style="font-size:1.15rem; font-weight:700; margin-bottom:1rem; color:var(--text-heading); display:flex; align-items:center; gap:0.5rem;">
            <i data-lucide="layers" style="width:20px; height:20px; color:var(--primary);"></i>
            Evaluación por Proyecto y Semáforo de Riesgo
        </h2>

        <div class="projects-grid">
            <div class="project-card">
                <div class="project-header">
                    <span class="project-name">
                        <i data-lucide="folder" style="width:18px; height:18px; color:var(--text-secondary);"></i>
                        Core bWAPP
                    </span>
                    <span class="status-pill status-critica">
                        <i data-lucide="shield-x" style="width:13px; height:13px;"></i> Postura Crítica
                    </span>
                </div>
                <div style="font-size:0.825rem; color:var(--text-secondary);">
                    Aplicación vulnerable principal (183 archivos PHP).
                </div>
                <div class="findings-bar">
                    <div class="bar-alta" style="width: 58.2%;"></div>
                    <div class="bar-media" style="width: 38.8%;"></div>
                    <div class="bar-baja" style="width: 3.0%;"></div>
                </div>
                <div style="display:flex; justify-content:space-between; font-size:0.825rem;">
                    <span><strong>103</strong> hallazgos</span>
                    <span style="color:var(--color-alta); font-weight:600;">60 Alta</span>
                    <span style="color:var(--color-media); font-weight:600;">40 Media</span>
                    <span style="color:var(--color-baja); font-weight:600;">3 Baja</span>
                </div>
                <p style="font-size:0.8rem; color:var(--text-body); margin-top:0.75rem; line-height:1.45;">
                    <strong>Justificación:</strong> SQLi masiva en endpoints críticos, RCE mediante <code>eval()</code> y <code>shell_exec()</code>, Inclusión de archivos y XSS. Bloqueo inmediato para producción.
                </p>
            </div>

            <div class="project-card">
                <div class="project-header">
                    <span class="project-name">
                        <i data-lucide="package" style="width:18px; height:18px; color:var(--text-secondary);"></i>
                        soap (NuSOAP)
                    </span>
                    <span class="status-pill status-alta">
                        <i data-lucide="shield-alert" style="width:13px; height:13px;"></i> Postura Alta
                    </span>
                </div>
                <div style="font-size:0.825rem; color:var(--text-secondary);">
                    Librería externa de servicios web SOAP (12 archivos PHP).
                </div>
                <div class="findings-bar">
                    <div class="bar-alta" style="width: 18.7%;"></div>
                    <div class="bar-media" style="width: 81.3%;"></div>
                    <div class="bar-baja" style="width: 0%;"></div>
                </div>
                <div style="display:flex; justify-content:space-between; font-size:0.825rem;">
                    <span><strong>32</strong> hallazgos</span>
                    <span style="color:var(--color-alta); font-weight:600;">6 Alta</span>
                    <span style="color:var(--color-media); font-weight:600;">26 Media</span>
                    <span style="color:var(--color-baja); font-weight:600;">0 Baja</span>
                </div>
                <p style="font-size:0.8rem; color:var(--text-body); margin-top:0.75rem; line-height:1.45;">
                    <strong>Justificación:</strong> Algoritmos de cifrado y hashing obsoletos (MD5/DES) y riesgo de componentes de terceros sin mantenimiento. Requiere triaje de falsos positivos en <code>base64</code>.
                </p>
            </div>

            <div class="project-card">
                <div class="project-header">
                    <span class="project-name">
                        <i data-lucide="settings" style="width:18px; height:18px; color:var(--text-secondary);"></i>
                        admin
                    </span>
                    <span class="status-pill status-media">
                        <i data-lucide="shield" style="width:13px; height:13px;"></i> Postura Media
                    </span>
                </div>
                <div style="font-size:0.825rem; color:var(--text-secondary);">
                    Panel de administración del sistema (3 archivos PHP).
                </div>
                <div class="findings-bar">
                    <div class="bar-alta" style="width: 0%;"></div>
                    <div class="bar-media" style="width: 66.7%;"></div>
                    <div class="bar-baja" style="width: 33.3%;"></div>
                </div>
                <div style="display:flex; justify-content:space-between; font-size:0.825rem;">
                    <span><strong>3</strong> hallazgos</span>
                    <span style="color:var(--color-alta); font-weight:600;">0 Alta</span>
                    <span style="color:var(--color-media); font-weight:600;">2 Media</span>
                    <span style="color:var(--color-baja); font-weight:600;">1 Baja</span>
                </div>
                <p style="font-size:0.8rem; color:var(--text-body); margin-top:0.75rem; line-height:1.45;">
                    <strong>Justificación:</strong> Credenciales embebidas por defecto (<code>password="bug"</code>) y fuga de configuración del servidor mediante llamada a <code>phpinfo()</code>.
                </p>
            </div>
        </div>

        <div style="background:var(--bg-surface); border:1px solid var(--border-subtle); border-radius:12px; padding:1.75rem; box-shadow:var(--shadow-sm);">
            <h3 style="font-size:1.05rem; color:var(--text-heading); margin-bottom:0.75rem; display:flex; align-items:center; gap:0.5rem;">
                <i data-lucide="clipboard-check" style="width:20px; height:20px; color:var(--primary);"></i>
                Lectura Ejecutiva y Prioridades de Remediación
            </h3>
            <p style="color:var(--text-body); font-size:0.875rem; margin-bottom:1.25rem; line-height:1.6;">
                La evaluación SAST demuestra que la aplicación presenta un nivel de vulnerabilidad inaceptable para un entorno corporativo. Con <strong>73 fallos de inyección (A03:2021)</strong> y un 48% de severidad alta, un atacante puede comprometer la base de datos y obtener ejecución remota de comandos en el servidor.
            </p>
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:1rem;">
                <div style="background:var(--bg-subtle); padding:1.1rem; border-radius:8px; border-left:3px solid var(--color-alta);">
                    <div style="font-weight:700; color:var(--text-heading); font-size:0.85rem; margin-bottom:0.25rem;">Prioridad 1: Consultas Preparadas (SQLi)</div>
                    <div style="font-size:0.8rem; color:var(--text-secondary);">
                        Parametrizar el 100% de consultas usando PDO o MySQLi Prepared Statements con <code>bind_param()</code>.
                    </div>
                </div>
                <div style="background:var(--bg-subtle); padding:1.1rem; border-radius:8px; border-left:3px solid var(--color-media);">
                    <div style="font-weight:700; color:var(--text-heading); font-size:0.85rem; margin-bottom:0.25rem;">Prioridad 2: Erradicar RCE y Comandos</div>
                    <div style="font-size:0.8rem; color:var(--text-secondary);">
                        Eliminar llamadas a <code>eval()</code> y sustituir <code>shell_exec()</code> por lógica nativa en PHP y validación de lista blanca.
                    </div>
                </div>
                <div style="background:var(--bg-subtle); padding:1.1rem; border-radius:8px; border-left:3px solid #f59e0b;">
                    <div style="font-weight:700; color:var(--text-heading); font-size:0.85rem; margin-bottom:0.25rem;">Prioridad 3: Sanitización y Codificación</div>
                    <div style="font-size:0.8rem; color:var(--text-secondary);">
                        Aplicar <code>htmlspecialchars($var, ENT_QUOTES, 'UTF-8')</code> en toda salida reflejada y sanear cabeceras HTTP.
                    </div>
                </div>
                <div style="background:var(--bg-subtle); padding:1.1rem; border-radius:8px; border-left:3px solid var(--primary);">
                    <div style="font-weight:700; color:var(--text-heading); font-size:0.85rem; margin-bottom:0.25rem;">Prioridad 4: Criptografía y Secretos</div>
                    <div style="font-size:0.8rem; color:var(--text-secondary);">
                        Migrar MD5/SHA1 a <code>password_hash(..., PASSWORD_ARGON2ID)</code> y extraer contraseñas a variables de entorno.
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- TAB 2: GRAFICAS -->
    <div id="tab-graficas" class="tab-panel">
        <div class="charts-grid">
            <div class="chart-card">
                <h3><i data-lucide="bar-chart" style="width:18px; height:18px; color:var(--primary);"></i> 01. Hallazgos por Proyecto y Severidad</h3>
                <div class="chart-img-wrap">
                    <img src="charts/01_proyecto_severidad.png" alt="Proyecto y Severidad">
                </div>
                <p style="font-size:0.8rem; color:var(--text-secondary); margin-top:0.75rem;">
                    El núcleo (Core) concentra 103 de los 138 hallazgos. Soap aporta principalmente hallazgos criptográficos.
                </p>
            </div>

            <div class="chart-card">
                <h3><i data-lucide="pie-chart" style="width:18px; height:18px; color:var(--primary);"></i> 02. Distribución OWASP Top 10 (2021)</h3>
                <div class="chart-img-wrap">
                    <img src="charts/02_owasp.png" alt="OWASP Top 10">
                </div>
                <p style="font-size:0.8rem; color:var(--text-secondary); margin-top:0.75rem;">
                    Dominancia absoluta de <strong>A03: Injection (73)</strong>, seguida de Fallos Criptográficos (29) y Control de Acceso (19).
                </p>
            </div>

            <div class="chart-card">
                <h3><i data-lucide="align-left" style="width:18px; height:18px; color:var(--primary);"></i> 03. Hallazgos por Tipo de Vulnerabilidad</h3>
                <div class="chart-img-wrap">
                    <img src="charts/03_tipo.png" alt="Tipo de Vulnerabilidad">
                </div>
                <p style="font-size:0.8rem; color:var(--text-secondary); margin-top:0.75rem;">
                    La Inyección SQL representa el vector individual más frecuente (50 hallazgos), seguido por hashing débil (24).
                </p>
            </div>

            <div class="chart-card">
                <h3><i data-lucide="donut" style="width:18px; height:18px; color:var(--primary);"></i> 04. Proporción por Severidad (Total)</h3>
                <div class="chart-img-wrap">
                    <img src="charts/04_severidad_donut.png" alt="Severidad Donut">
                </div>
                <p style="font-size:0.8rem; color:var(--text-secondary); margin-top:0.75rem;">
                    48% de severidad Alta (66) y 49% Media (68). Solo un 3% corresponde a hallazgos informativos/bajos.
                </p>
            </div>

            <div class="chart-card" style="grid-column: 1 / -1;">
                <h3><i data-lucide="file-warning" style="width:18px; height:18px; color:var(--primary);"></i> 05. Top 10 Archivos con Mayor Deuda de Seguridad (Core bWAPP)</h3>
                <div class="chart-img-wrap">
                    <img src="charts/05_top_archivos.png" alt="Top Archivos">
                </div>
                <p style="font-size:0.8rem; color:var(--text-secondary); margin-top:0.75rem;">
                    Priorización directa para refactorización: <code>ba_forgotten.php</code>, <code>ba_weak_pwd.php</code>, <code>user_extra.php</code> y <code>user_new.php</code> encabezan la lista de intervención.
                </p>
            </div>
        </div>
    </div>

    <!-- TAB 3: EXPLORADOR DE HALLAZGOS -->
    <div id="tab-hallazgos" class="tab-panel">
        <div class="controls-bar">
            <div class="search-box">
                <i data-lucide="search" class="search-icon-pos"></i>
                <input type="text" id="searchInput" placeholder="Buscar por archivo, regla, CWE, mensaje..." onkeyup="filterTable()">
            </div>
            <select class="filter-select" id="projFilter" onchange="filterTable()">
                <option value="">Todos los Proyectos</option>
                <option value="Core bWAPP">Core bWAPP (103)</option>
                <option value="soap (NuSOAP)">soap - NuSOAP (32)</option>
                <option value="admin">admin (3)</option>
            </select>
            <select class="filter-select" id="sevFilter" onchange="filterTable()">
                <option value="">Todas las Severidades</option>
                <option value="Alta">Alta (66)</option>
                <option value="Media">Media (68)</option>
                <option value="Baja">Baja (4)</option>
            </select>
            <span id="findingsCount" style="font-size:0.825rem; font-weight:600; color:var(--text-secondary);">138 hallazgos</span>
        </div>

        <div class="table-wrap">
            <table id="findingsTable">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Severidad</th>
                        <th>Proyecto</th>
                        <th>Archivo : Línea</th>
                        <th>Regla / Categoría</th>
                        <th>OWASP / CWE</th>
                        <th>Detalle & Mensaje</th>
                    </tr>
                </thead>
                <tbody id="tableBody">
                    <!-- Dynamic rows inserted by JS -->
                </tbody>
            </table>
        </div>
    </div>

    <!-- TAB 4: 5 CASOS DESTACADOS & REMEDIACIÓN -->
    <div id="tab-casos" class="tab-panel">
        <h2 style="font-size:1.15rem; font-weight:700; margin-bottom:1rem; color:var(--text-heading); display:flex; align-items:center; gap:0.5rem;">
            <i data-lucide="code-2" style="width:20px; height:20px; color:var(--primary);"></i>
            T5 — Análisis Profundo de 5 Vulnerabilidades y Código Remediado
        </h2>

        <!-- Caso 1 -->
        <div class="vuln-case-card">
            <div class="vuln-case-header">
                <div>
                    <span class="sev-badge sev-Alta">Alta · Error</span>
                    <h3 class="vuln-title" style="display:inline; margin-left:0.5rem;">1. SQL Injection — sqli_1.php</h3>
                </div>
                <div>
                    <span class="code-pill">OWASP A03:2021 – Injection</span>
                    <span class="code-pill">CWE-89</span>
                </div>
            </div>
            <p style="font-size:0.85rem; color:var(--text-body); line-height:1.5;">
                <strong>Vector de Ataque:</strong> La variable <code>$_GET["title"]</code> se concatena directamente en la cadena SQL. La función <code>sqli()</code> no implementa saneamiento en nivel de seguridad "low", permitiendo extracción de tablas mediante <code>UNION SELECT</code> o bypass de autenticación.
            </p>
            <div class="code-grid">
                <div class="code-block">
                    <div class="code-header vuln"><span>Vulnerable (bWAPP/sqli_1.php:60)</span><i data-lucide="x-circle" style="width:14px; height:14px;"></i></div>
                    <pre><code>$title = $_GET["title"];
$sql = "SELECT * FROM movies WHERE title LIKE '%" . sqli($title) . "%'";
$recordset = mysql_query($sql, $link);</code></pre>
                </div>
                <div class="code-block">
                    <div class="code-header fix"><span>Remediado (Sentencias Preparadas MySQLi / PDO)</span><i data-lucide="check-circle-2" style="width:14px; height:14px;"></i></div>
                    <pre><code>$title = $_GET["title"] ?? "";
$stmt = $mysqli->prepare("SELECT * FROM movies WHERE title LIKE ?");
$like_title = "%" . $title . "%";
$stmt->bind_param("s", $like_title);
$stmt->execute();
$recordset = $stmt->get_result();</code></pre>
                </div>
            </div>
        </div>

        <!-- Caso 2 -->
        <div class="vuln-case-card">
            <div class="vuln-case-header">
                <div>
                    <span class="sev-badge sev-Alta">Alta · Error</span>
                    <h3 class="vuln-title" style="display:inline; margin-left:0.5rem;">2. OS Command Injection — commandi.php</h3>
                </div>
                <div>
                    <span class="code-pill">OWASP A03:2021 – Injection</span>
                    <span class="code-pill">CWE-78</span>
                </div>
            </div>
            <p style="font-size:0.85rem; color:var(--text-body); line-height:1.5;">
                <strong>Vector de Ataque:</strong> Entrada proveniente de <code>$_POST["target"]</code> se pasa sin delimitar al intérprete del sistema operativo mediante <code>shell_exec()</code>. Un atacante puede encadenar comandos usando metacaracteres (<code>; id</code>, <code>| whoami</code>).
            </p>
            <div class="code-grid">
                <div class="code-block">
                    <div class="code-header vuln"><span>Vulnerable (bWAPP/commandi.php:40)</span><i data-lucide="x-circle" style="width:14px; height:14px;"></i></div>
                    <pre><code>$target = $_POST["target"];
echo "&lt;p&gt;" . shell_exec("nslookup  " . commandi($target)) . "&lt;/p&gt;";</code></pre>
                </div>
                <div class="code-block">
                    <div class="code-header fix"><span>Remediado (Lista Blanca + Escapado de Argumentos)</span><i data-lucide="check-circle-2" style="width:14px; height:14px;"></i></div>
                    <pre><code>$target = trim($_POST["target"] ?? "");
if (!filter_var($target, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) &amp;&amp; 
    !filter_var($target, FILTER_VALIDATE_IP)) {{
    die("Destino no válido");
}}
$safe_target = escapeshellarg($target);
echo "&lt;p&gt;" . htmlspecialchars(shell_exec("nslookup " . $safe_target)) . "&lt;/p&gt;";</code></pre>
                </div>
            </div>
        </div>

        <!-- Caso 3 -->
        <div class="vuln-case-card">
            <div class="vuln-case-header">
                <div>
                    <span class="sev-badge sev-Alta">Alta · Error</span>
                    <h3 class="vuln-title" style="display:inline; margin-left:0.5rem;">3. Dynamic Code Execution (RCE) — php_eval.php</h3>
                </div>
                <div>
                    <span class="code-pill">OWASP A03:2021 – Injection</span>
                    <span class="code-pill">CWE-95</span>
                </div>
            </div>
            <p style="font-size:0.85rem; color:var(--text-body); line-height:1.5;">
                <strong>Vector de Ataque:</strong> El parámetro <code>$_REQUEST["eval"]</code> se pasa directamente a la función <code>eval()</code>, lo que otorga Ejecución Remota de Código (RCE) completa e inmediata al atacante en el contexto del servidor web.
            </p>
            <div class="code-grid">
                <div class="code-block">
                    <div class="code-header vuln"><span>Vulnerable (bWAPP/php_eval.php:48)</span><i data-lucide="x-circle" style="width:14px; height:14px;"></i></div>
                    <pre><code>@eval($_REQUEST["eval"]);</code></pre>
                </div>
                <div class="code-block">
                    <div class="code-header fix"><span>Remediado (Despachador Seguro - Eliminación de eval)</span><i data-lucide="check-circle-2" style="width:14px; height:14px;"></i></div>
                    <pre><code>// No existe uso seguro para eval() con datos provistos por clientes.
$action = $_REQUEST["action"] ?? "default";
$allowed_actions = ["calcular" => "func_calc", "mostrar" => "func_show"];
if (array_key_exists($action, $allowed_actions)) {{
    call_user_func($allowed_actions[$action]);
}}</code></pre>
                </div>
            </div>
        </div>

        <!-- Caso 4 -->
        <div class="vuln-case-card">
            <div class="vuln-case-header">
                <div>
                    <span class="sev-badge sev-Media">Media · Warning</span>
                    <h3 class="vuln-title" style="display:inline; margin-left:0.5rem;">4. Reflected Cross-Site Scripting (XSS) — xss_get.php</h3>
                </div>
                <div>
                    <span class="code-pill">OWASP A03:2021 – Injection</span>
                    <span class="code-pill">CWE-79</span>
                </div>
            </div>
            <p style="font-size:0.85rem; color:var(--text-body); line-height:1.5;">
                <strong>Vector de Ataque:</strong> El valor de <code>$_GET["firstname"]</code> se concatena directamente en la respuesta HTML sin codificar caracteres especiales (<code>&lt;</code>, <code>&gt;</code>, <code>"</code>, <code>'</code>), permitiendo inyección de scripts JavaScript en el navegador de la víctima.
            </p>
            <div class="code-grid">
                <div class="code-block">
                    <div class="code-header vuln"><span>Vulnerable (bWAPP/xss_get.php:45)</span><i data-lucide="x-circle" style="width:14px; height:14px;"></i></div>
                    <pre><code>$firstname = $_GET["firstname"];
echo "Welcome " . xss($firstname) . " " . xss($lastname);</code></pre>
                </div>
                <div class="code-block">
                    <div class="code-header fix"><span>Remediado (Codificación Contextual HTML5)</span><i data-lucide="check-circle-2" style="width:14px; height:14px;"></i></div>
                    <pre><code>$firstname = $_GET["firstname"] ?? "";
$lastname = $_GET["lastname"] ?? "";
echo "Welcome " . htmlspecialchars($firstname, ENT_QUOTES | ENT_HTML5, 'UTF-8') . " " . 
     htmlspecialchars($lastname, ENT_QUOTES | ENT_HTML5, 'UTF-8');</code></pre>
                </div>
            </div>
        </div>

        <!-- Caso 5 -->
        <div class="vuln-case-card">
            <div class="vuln-case-header">
                <div>
                    <span class="sev-badge sev-Alta">Alta · Error</span>
                    <h3 class="vuln-title" style="display:inline; margin-left:0.5rem;">5. Local / Remote File Inclusion (LFI/RFI) — directory_traversal_1.php</h3>
                </div>
                <div>
                    <span class="code-pill">OWASP A01:2021 – Broken Access Control</span>
                    <span class="code-pill">CWE-22 / CWE-98</span>
                </div>
            </div>
            <p style="font-size:0.85rem; color:var(--text-body); line-height:1.5;">
                <strong>Vector de Ataque:</strong> El archivo a incluir proviene de un parámetro externo sin validación de secuencia de escape de directorios (<code>../../etc/passwd</code> o URLs remotas).
            </p>
            <div class="code-grid">
                <div class="code-block">
                    <div class="code-header vuln"><span>Vulnerable (bWAPP/directory_traversal_1.php:40)</span><i data-lucide="x-circle" style="width:14px; height:14px;"></i></div>
                    <pre><code>$file = $_GET["page"];
include($file);</code></pre>
                </div>
                <div class="code-block">
                    <div class="code-header fix"><span>Remediado (Lista Blanca y basename)</span><i data-lucide="check-circle-2" style="width:14px; height:14px;"></i></div>
                    <pre><code>$file = basename($_GET["page"] ?? "home.php");
$allowed_pages = ["home.php", "about.php", "contact.php"];
if (!in_array($file, $allowed_pages, true)) {{
    http_response_code(400);
    die("Página no permitida");
}}
include(__DIR__ . "/pages/" . $file);</code></pre>
                </div>
            </div>
        </div>
    </div>

    <!-- TAB 5: TRIAJE DE FALSO POSITIVO -->
    <div id="tab-triaje" class="tab-panel">
        <div style="background:var(--bg-surface); border:1px solid var(--border-subtle); border-radius:12px; padding:2rem; box-shadow:var(--shadow-sm);">
            <div style="display:flex; align-items:center; gap:0.75rem; margin-bottom:1rem;">
                <span class="status-pill status-alta"><i data-lucide="alert-circle" style="width:13px; height:13px;"></i> T6 — Triaje Crítico</span>
                <h2 style="color:var(--text-heading); font-size:1.25rem; font-weight:700;">Falso Positivo en Regla Criptográfica: base64_encode()</h2>
            </div>
            <p style="color:var(--text-body); font-size:0.9rem; line-height:1.6; margin-bottom:1.5rem;">
                En la evaluación SAST sobre la librería <strong>soap (NuSOAP)</strong>, la regla de criptografía <code>php-weak-crypto-mcrypt</code> marca 5 coincidencias sobre el uso de <code>base64_encode()</code> y <code>base64_decode()</code>, catalogándolos con severidad media o alta.
            </p>
            
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:1.5rem; margin-bottom:1.5rem;">
                <div style="background:var(--bg-subtle); border:1px solid var(--border-subtle); border-radius:8px; padding:1.25rem;">
                    <h4 style="color:var(--color-alta); margin-bottom:0.6rem; font-size:0.9rem; display:flex; align-items:center; gap:0.4rem;">
                        <i data-lucide="x-octagon" style="width:16px; height:16px;"></i> Justificación Técnica del Falso Positivo
                    </h4>
                    <ul style="font-size:0.825rem; color:var(--text-body); padding-left:1.2rem; line-height:1.6;">
                        <li><strong>Base64 no es un algoritmo criptográfico:</strong> Es un esquema de <em>codificación de contenido binario a texto ASCII</em> (RFC 4648).</li>
                        <li><strong>Propósito en SOAP/XML:</strong> XML solo admite caracteres imprimibles. NuSOAP usa Base64 para transportar adjuntos y binarios de forma transparente en HTTP.</li>
                        <li><strong>No provee confidencialidad por diseño:</strong> Clasificarlo como "cifrado roto o débil" es conceptualmente erróneo en el contexto de transmisión de datos.</li>
                    </ul>
                </div>
                <div style="background:var(--bg-subtle); border:1px solid var(--border-subtle); border-radius:8px; padding:1.25rem;">
                    <h4 style="color:var(--color-success); margin-bottom:0.6rem; font-size:0.9rem; display:flex; align-items:center; gap:0.4rem;">
                        <i data-lucide="check-square" style="width:16px; height:16px;"></i> Ajuste Propuesto al Ruleset YAML
                    </h4>
                    <p style="font-size:0.825rem; color:var(--text-body); margin-bottom:0.5rem;">
                        Añadir cláusulas <code>pattern-not</code> para excluir funciones de codificación de transporte o separar en una regla informativa:
                    </p>
                    <pre style="background:#0f172a; border-radius:6px; font-size:0.75rem; padding:0.6rem; color:#f8fafc;"><code>rules:
  - id: php-weak-crypto-mcrypt
    pattern-not: base64_encode(...)
    pattern-not: base64_decode(...)
    pattern-sinks:
      - pattern: mcrypt_encrypt(...)
      - pattern: des_encrypt(...)</code></pre>
                </div>
            </div>
            
            <div style="background:var(--primary-light); border:1px solid var(--primary-border); border-radius:8px; padding:1rem; font-size:0.85rem; color:#1e40af; display:flex; align-items:flex-start; gap:0.6rem;">
                <i data-lucide="lightbulb" style="width:20px; height:20px; flex-shrink:0; margin-top:0.1rem;"></i>
                <div>
                    <strong>Lección de Seguridad de Aplicaciones:</strong> Las herramientas SAST operan mediante coincidencia de patrones y flujos de datos. La intervención de un analista de seguridad (triaje humano) es indispensable para validar hallazgos antes de reportarlos al equipo de ingeniería, evitando fricción y fatiga de alertas.
                </div>
            </div>
        </div>
    </div>

    <!-- TAB 6: MODO EXPOSICIÓN -->
    <div id="tab-exposicion" class="tab-panel">
        <div class="presentation-container">
            <!-- Slide 1 -->
            <div class="slide active" id="slide-1">
                <div class="slide-tag"><i data-lucide="bookmark" style="width:14px; height:14px;"></i> Diapositiva 1 de 6 · Portada</div>
                <h2 class="slide-title">Auditoría Estática de Código (SAST) con Semgrep sobre bWAPP</h2>
                <div class="slide-body">
                    <p><strong>Curso:</strong> Seguridad de Aplicaciones | Universidad Mariano Gálvez de Guatemala</p>
                    <p><strong>Expositor:</strong> Josias Suhul</p>
                    <p style="margin-top:1rem;"><strong>Objetivo:</strong> Evaluar de forma automatizada y estructurada el código fuente de una aplicación web vulnerable (bWAPP) usando Semgrep, mapeando debilidades hacia OWASP Top 10 y CWE para emitir una postura de seguridad corporativa.</p>
                </div>
            </div>

            <!-- Slide 2 -->
            <div class="slide" id="slide-2">
                <div class="slide-tag"><i data-lucide="cpu" style="width:14px; height:14px;"></i> Diapositiva 2 de 6 · Arquitectura y Reglas</div>
                <h2 class="slide-title">¿Cómo Funciona Semgrep? Patrones vs Taint Tracking</h2>
                <div class="slide-body">
                    <ul>
                        <li><strong>Análisis Sintáctico:</strong> Busca construcciones inseguras directas como <code>eval()</code> o <code>phpinfo()</code> sin depender de su contexto de llamada.</li>
                        <li><strong>Taint Mode (Seguimiento de Datos):</strong> Rastrea datos no confiables desde <em>sources</em> (<code>$_GET</code>, <code>$_POST</code>) hasta puntos de ejecución peligrosos (<em>sinks</em> como <code>mysqli_query</code> o <code>system</code>).</li>
                        <li><strong>Ruleset del Laboratorio:</strong> 14 reglas locales en YAML mapeadas estrictamente a estándares de la industria (OWASP 2021 y catálogo CWE de MITRE).</li>
                    </ul>
                </div>
            </div>

            <!-- Slide 3 -->
            <div class="slide" id="slide-3">
                <div class="slide-tag"><i data-lucide="bar-chart-2" style="width:14px; height:14px;"></i> Diapositiva 3 de 6 · Resultados Globales</div>
                <h2 class="slide-title">Resultados del Escaneo: 138 Hallazgos en 198 Archivos</h2>
                <div class="slide-body">
                    <ul>
                        <li><strong>Core bWAPP:</strong> 103 hallazgos (60 Alta, 40 Media, 3 Baja) — Concentra las inyecciones más críticas.</li>
                        <li><strong>soap (NuSOAP):</strong> 32 hallazgos — Librería externa que introduce debilidad por cifrado deprecado.</li>
                        <li><strong>admin:</strong> 3 hallazgos — Exposición de configuración técnica y contraseñas quemadas.</li>
                        <li><strong>Distribución:</strong> Prácticamente el 50% de las vulnerabilidades son de severidad <strong>Alta</strong>, dominadas por <strong>A03: Injection (73)</strong>.</li>
                    </ul>
                </div>
            </div>

            <!-- Slide 4 -->
            <div class="slide" id="slide-4">
                <div class="slide-tag"><i data-lucide="shield-check" style="width:14px; height:14px;"></i> Diapositiva 4 de 6 · Hallazgos y Remediación</div>
                <h2 class="slide-title">Casos Críticos: De la Detección a la Corrección</h2>
                <div class="slide-body">
                    <ul>
                        <li><strong>Inyección SQL (sqli_1.php):</strong> Se soluciona migrando a consultas preparadas (Prepared Statements con PDO/MySQLi).</li>
                        <li><strong>Inyección de Comandos (commandi.php):</strong> Evitar <code>shell_exec</code>; aplicar validación con lista blanca y <code>escapeshellarg()</code>.</li>
                        <li><strong>Ejecución de Código (php_eval.php):</strong> RCE directo; se remueve completamente el uso de <code>eval()</code>.</li>
                        <li><strong>XSS Reflejado (xss_get.php):</strong> Codificación contextual mediante <code>htmlspecialchars()</code> con bandera ENT_QUOTES.</li>
                    </ul>
                </div>
            </div>

            <!-- Slide 5 -->
            <div class="slide" id="slide-5">
                <div class="slide-tag"><i data-lucide="filter" style="width:14px; height:14px;"></i> Diapositiva 5 de 6 · Triaje y Ajuste</div>
                <h2 class="slide-title">Triaje Técnico: Descartando Falsos Positivos</h2>
                <div class="slide-body">
                    <ul>
                        <li>La regla de cifrado débil alertó sobre llamadas a <code>base64_encode()</code> en NuSOAP.</li>
                        <li><strong>Conclusión del Analista:</strong> Base64 es un mecanismo de transporte para XML/SOAP, no un algoritmo criptográfico.</li>
                        <li><strong>Acción Correctiva:</strong> Ajuste del archivo YAML de reglas mediante filtros <code>pattern-not</code> para refinar la precisión del escáner y reducir la fatiga de alertas.</li>
                    </ul>
                </div>
            </div>

            <!-- Slide 6 -->
            <div class="slide" id="slide-6">
                <div class="slide-tag"><i data-lucide="flag" style="width:14px; height:14px;"></i> Diapositiva 6 de 6 · Postura Ejecutiva</div>
                <h2 class="slide-title">Postura de Seguridad y Hoja de Ruta</h2>
                <div class="slide-body">
                    <ul>
                        <li><strong>Índice Ponderado:</strong> 538 puntos de riesgo.</li>
                        <li><strong>Dictamen:</strong> <strong>Crítico (Bloqueo de Despliegue)</strong>. La aplicación no cumple con los requisitos mínimos de seguridad.</li>
                        <li><strong>Integración en CI/CD:</strong> Se configuró un pipeline de GitHub Actions (<code>semgrep.yml</code>) que escanea automáticamente cada Pull Request y publica reportes SARIF.</li>
                    </ul>
                </div>
            </div>

            <div class="slide-controls">
                <button class="btn btn-secondary" onclick="prevSlide()"><i data-lucide="arrow-left"></i> Anterior</button>
                <span id="slideIndicator" style="font-size:0.85rem; font-weight:600; color:var(--text-secondary);">1 / 6</span>
                <button class="btn" onclick="nextSlide()">Siguiente <i data-lucide="arrow-right"></i></button>
            </div>
        </div>
    </div>
</main>

<script>
    const allFindings = {findings_json_str};

    function switchTab(tabName) {{
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
        document.getElementById('tab-' + tabName).classList.add('active');
        event.currentTarget.classList.add('active');
        lucide.createIcons();
    }}

    function renderTable(items) {{
        const tbody = document.getElementById('tableBody');
        tbody.innerHTML = '';
        items.forEach(f => {{
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><span class="code-pill">#${{f.id}}</span></td>
                <td><span class="sev-badge sev-${{f.severity}}">${{f.severity}}</span></td>
                <td><span style="font-weight:600; font-size:0.825rem; color:var(--text-heading);">${{f.project}}</span></td>
                <td><code style="color:var(--primary); font-size:0.8rem; font-weight:600;">${{f.file}}:${{f.line_start}}</code></td>
                <td><strong style="color:var(--text-heading);">${{f.category}}</strong><br><span style="font-size:0.75rem; color:var(--text-secondary);">${{f.rule_short}}</span></td>
                <td><span class="code-pill">${{f.owasp.split(' - ')[0]}}</span><br><span class="code-pill">${{f.cwe}}</span></td>
                <td style="max-width:320px; font-size:0.8rem; color:var(--text-body);">${{f.message}}</td>
            `;
            tbody.appendChild(tr);
        }});
        document.getElementById('findingsCount').innerText = `${{items.length}} hallazgos`;
    }}

    function filterTable() {{
        const q = document.getElementById('searchInput').value.toLowerCase();
        const proj = document.getElementById('projFilter').value;
        const sev = document.getElementById('sevFilter').value;

        const filtered = allFindings.filter(f => {{
            const matchQ = !q || f.file.toLowerCase().includes(q) || 
                                 f.message.toLowerCase().includes(q) || 
                                 f.category.toLowerCase().includes(q) || 
                                 f.cwe.toLowerCase().includes(q) ||
                                 f.rule_short.toLowerCase().includes(q);
            const matchProj = !proj || f.project === proj;
            const matchSev = !sev || f.severity === sev;
            return matchQ && matchProj && matchSev;
        }});
        renderTable(filtered);
    }}

    // Slides logic
    let curSlide = 1;
    const totalSlides = 6;
    function updateSlide() {{
        for (let i = 1; i <= totalSlides; i++) {{
            const s = document.getElementById('slide-' + i);
            if (s) s.classList.toggle('active', i === curSlide);
        }}
        document.getElementById('slideIndicator').innerText = `${{curSlide}} / ${{totalSlides}}`;
        lucide.createIcons();
    }}
    function nextSlide() {{
        if (curSlide < totalSlides) {{ curSlide++; updateSlide(); }}
    }}
    function prevSlide() {{
        if (curSlide > 1) {{ curSlide--; updateSlide(); }}
    }}

    // Init
    window.onload = function() {{
        renderTable(allFindings);
        lucide.createIcons();
    }};
</script>
</body>
</html>
"""

with open("index.html", "w", encoding="utf-8") as f:
    f.write(html_content)

print(f"OK generated index.html without emojis, with light theme and Lucide icons ({len(clean_findings)} findings)")
