# Laboratorio de SAST con Semgrep — Análisis de Código de bWAPP

[![Semgrep SAST Scan](https://github.com/jsuhula/lab-segap-07/actions/workflows/semgrep.yml/badge.svg)](https://github.com/jsuhula/lab-segap-07/actions/workflows/semgrep.yml)
[![OWASP Top 10 2021](https://img.shields.io/badge/OWASP%20Top%2010-2021%20Compliant-blue.svg)](https://owasp.org/Top10/)
[![Semgrep Engine](https://img.shields.io/badge/Semgrep-1.185.0-success.svg)](https://semgrep.dev)
[![Academic Project](https://img.shields.io/badge/UMG-Seguridad%20de%20Aplicaciones-red.svg)](https://umg.edu.gt/)

Repositorio oficial para el desarrollo del **Laboratorio 07: Práctica de SAST (Static Application Security Testing) con Semgrep sobre bWAPP**, correspondiente al curso de **Seguridad de Aplicaciones** en la **Universidad Mariano Gálvez de Guatemala**.

---

## 📌 Tabla de Contenidos
1. [Objetivo y Alcance](#-objetivo-y-alcance)
2. [Estructura del Repositorio](#-estructura-del-repositorio)
3. [Resumen de Resultados y Métricas](#-resumen-de-resultados-y-métricas)
4. [Reproducción Rápida de Escaneos](#-reproducción-rápida-de-escaneos)
5. [Dashboard Interactivo (T8)](#-dashboard-interactivo-t8)
6. [Integración Continua con CI/CD (Bonus)](#-integración-continua-con-cicd-bonus)
7. [Informe Técnico Completo](#-informe-técnico-completo)

---

## 🎯 Objetivo y Alcance

Realizar una auditoría estática de código automatizada (SAST) mediante el motor de reglas **Semgrep** sobre el código fuente de **bWAPP** (*buggy Web Application*), evaluando 3 componentes del sistema:
- **Core bWAPP (`bWAPP-app/`):** Aplicación web vulnerable principal (183 archivos PHP auditados).
- **admin (`bWAPP-app/admin/`):** Panel de administración del sistema (3 archivos PHP).
- **soap (`bWAPP-app/soap/`):** Componente de servicios web de terceros NuSOAP (12 archivos PHP).

El análisis identifica vulnerabilidades críticas mapeadas hacia los estándares internacionales **OWASP Top 10 (2021)** y el catálogo **CWE de MITRE**, clasificando hallazgos por severidad y proponiendo remediaciones seguras a nivel de código.

---

## 📂 Estructura del Repositorio

```text
lab-segap-07/
├── .github/
│   └── workflows/
│       └── semgrep.yml             # Pipeline CI/CD para GitHub Actions
├── bWAPP-app/                      # Código fuente PHP de bWAPP auditado
│   ├── admin/                      # Subproyecto Admin
│   ├── soap/                       # Subproyecto Soap (NuSOAP)
│   └── ...                         # Subproyecto Core
├── charts/                         # Gráficas estadísticas generadas por matplotlib
│   ├── 01_proyecto_severidad.png
│   ├── 02_owasp.png
│   ├── 03_tipo.png
│   ├── 04_severidad_donut.png
│   └── 05_top_archivos.png
├── screens/                        # Capturas de ejecución en terminal y plataforma web
├── semgrep/
│   ├── out/                        # Salidas en formato JSON y SARIF
│   │   ├── admin.json / admin.sarif
│   │   ├── core.json / core.sarif
│   │   └── soap.json
│   ├── analyze.py                  # Script de agregación y generación de gráficas
│   ├── php-sast-rules.yml          # Ruleset de 14 reglas Semgrep (taint y patrón)
│   └── summary.json                # Resumen agregado de métricas
├── index.html                      # Dashboard navegable interactivo (T8)
├── build_dashboard.py              # Generador del dashboard HTML
├── php-sast-rules.yml              # Copia raíz del ruleset para ejecución directa
├── INFORME_LABORATORIO_SAST_SEMGREP.md # Informe técnico formal (T1 a T8)
└── README.md                       # Documentación principal
```

---

## 📊 Resumen de Resultados y Métricas

La auditoría analizó un total de **198 archivos PHP**, detectando **138 hallazgos** con un **Índice Ponderado de Riesgo de 538 puntos**:

$$\text{Índice Ponderado} = (\text{Alta} \times 5) + (\text{Media} \times 3) + (\text{Baja} \times 1) = (66 \times 5) + (68 \times 3) + (4 \times 1) = 538 \text{ pts}$$

| Proyecto | Archivos PHP | Total Hallazgos | Alta (ERROR) | Media (WARN) | Baja (INFO) | Postura de Seguridad | Justificación Principal |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Core bWAPP** | 183 | **103** | 60 | 40 | 3 | 🔴 **Crítica** | SQLi masiva, RCE (`eval`, `shell_exec`), LFI, XSS |
| **soap (NuSOAP)** | 12 | **32** | 6 | 26 | 0 | 🟠 **Alta** | Cripto débil (MD5/DES) y riesgo en componentes de terceros |
| **admin** | 3 | **3** | 0 | 2 | 1 | 🟡 **Media** | Credenciales quemadas en código y fuga mediante `phpinfo` |
| **TOTAL** | **198** | **138** | **66** | **68** | **4** | 🔴 **Crítica Global** | **Bloqueo inmediato de paso a producción** |

### Distribución por Categoría OWASP Top 10 (2021)
1. **A03:2021 – Injection:** 73 hallazgos (SQLi, Commandi, Code Injection, LDAP, Mail)
2. **A02:2021 – Cryptographic Failures:** 29 hallazgos (Weak Hash, Cifrado débil)
3. **A01:2021 – Broken Access Control:** 19 hallazgos (Open Redirect, File Inclusion)
4. **A07:2021 – Identification & Auth Failures:** 13 hallazgos (Hardcoded Credentials)
5. **A05:2021 – Security Misconfiguration:** 4 hallazgos (Information Disclosure / `phpinfo`)

---

## 🚀 Reproducción Rápida de Escaneos

### 1. Requisitos Previos
- Python 3.9+ instalado.
- Semgrep instalado: `pip install semgrep`
- Matplotlib (para regenerar gráficas): `pip install matplotlib`

### 2. Comandos de Escaneo SAST
```bash
# Variables de configuración recomendadas
R=php-sast-rules.yml
OFF="--metrics=off --disable-version-check --no-git-ignore"

# Escaneo de Proyecto 1: Core bWAPP (excluyendo admin y soap)
semgrep scan --config $R $OFF --exclude admin --exclude soap --json -o semgrep/out/core.json bWAPP-app

# Escaneo de Proyecto 2: admin
semgrep scan --config $R $OFF --json -o semgrep/out/admin.json bWAPP-app/admin

# Escaneo de Proyecto 3: soap (NuSOAP)
semgrep scan --config $R $OFF --json -o semgrep/out/soap.json bWAPP-app/soap

# Regenerar gráficas y métricas
python semgrep/analyze.py
```

---

## 🖥️ Dashboard Interactivo (T8)

Para desplegar y visualizar los resultados de la auditoría en un entorno navegable y enriquecido:
- Abra el archivo [`index.html`](index.html) directamente en su navegador web favorito.
- Características incluidas:
  - **Métricas Ejecutivas:** Tarjetas de postura de riesgo, semáforo y distribución.
  - **Galería de Gráficas Oficiales:** Visualizador de las 5 gráficas analíticas.
  - **Explorador Dinámico de Hallazgos:** Filtros en tiempo real por proyecto, severidad y búsqueda por texto.
  - **Fichas Técnicas de Remediación:** Comparativa lado a lado entre código vulnerable y código corregido.
  - **Triaje de Falso Positivo:** Explicación técnica del caso `base64_encode()`.
  - **Modo Presentador:** Vista estructurada diapositiva a diapositiva para la exposición ante el grupo.

---

## 🔄 Integración Continua con CI/CD (Bonus +5 pts)

El repositorio incluye el flujo de automatización [`.github/workflows/semgrep.yml`](.github/workflows/semgrep.yml) que implementa:
1. Disparo ante eventos `push` o `pull_request` sobre la rama `main`.
2. Instalación desatendida del motor Semgrep.
3. Escaneo SAST del código fuente con salida en formato estándar **SARIF**.
4. Carga automática de hallazgos mediante `github/codeql-action/upload-sarif@v3` para visualización nativa en la pestaña **Security → Code scanning alerts** de GitHub.

---

## 📄 Informe Técnico Completo

Consulte el documento detallado [INFORME_LABORATORIO_SAST_SEMGREP.md](INFORME_LABORATORIO_SAST_SEMGREP.md) que contiene el desarrollo punto por punto de las 8 tareas (T1 a T8), justificaciones técnicas, código remediado y conclusiones del análisis.

---
**Universidad Mariano Gálvez de Guatemala** · Maestría / Diplomado en Ciberseguridad · Curso: *Seguridad de Aplicaciones*  
Estudiante: **Josias Suhul** · 2026
