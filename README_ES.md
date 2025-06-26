[🇫🇷 Français](https://github.com/karim93160/ip-nose/blob/main/README.md) | [🇬🇧 English](https://github.com/karim93160/ip-nose/blob/main/README_EN.md) | [🇪🇸 Español](https://github.com/karim93160/ip-nose/blob/main/README_ES.md)

<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Dash-0062FF?style=for-the-badge&logo=plotly&logoColor=white" alt="Dash Plotly">
  <img src="https://img.shields.io/badge/Cybersecurity-00CED1?style=for-the-badge&logo=hackthebox&logoColor=white" alt="Cybersecurity">
  <img src="https://img.shields.io/badge/Termux-20C20E?style=for-the-badge&logo=android&logoColor=white" alt="Termux">
  <img src="https://img.shields.io/github/stars/karim93160/hacker-suite-2000?style=for-the-badge" alt="Stars">
  <img src="https://img.shields.io/github/forks/karim93160/hacker-suite-2000?style=for-the-badge" alt="Forks">
</p>

### 🚀HACKER-SUITE+2000🚀

---

<p align="center">
  <img src="https://github.com/Karim93160/Dark-Web/raw/56bcada59bf637cfddc36b7c3e04c6df5277b041/hacker_output.gif" alt="Hacker-Suite+2000 Demonstration" width="700"/>
</p>

---

<p align="center">
<img src="https://img.shields.io/badge/Python-3.8+-informational?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+ Requerido">
<img src="https://img.shields.io/badge/Interfaz-Web%20Dash-blueviolet?style=for-the-badge" alt="Interfaz Web Dash">
<img src="https://img.shields.io/badge/Exfiltración-HTTPS%2FDNS-green?style=for-the-badge" alt="Exfiltración HTTPS/DNS">
</p>

---

## 📦 Instalación
Sigue estos pasos para configurar y lanzar HACKER-SUITE+2000.
Preparación de Termux (Android)
Si estás usando Termux en Android, puedes ejecutar el script de configuración incluido para facilitar la instalación de las herramientas necesarias:
 * Abre Termux.
 * Clona el repositorio (si no lo has hecho ya):

```
git clone https://github.com/karim93160/hacker-suite-2000.git
cd hacker-suite-2000
```

 * Ejecuta el script:

```
setup_termux.sh:
chmod +x setup_termux.sh
./setup_termux.sh
```

Este script instalará python, pip y otras herramientas del sistema si son necesarias.

---

## 🚀 Iniciando la Aplicación

Para iniciar el panel de control de HACKER-SUITE+2000, navega al directorio principal del proyecto y ejecuta:

```
control_panel.py
```

Recomendamos ejecutarlo en segundo plano para que puedas cerrar tu terminal sin detener la aplicación (asegúrate de estar en el directorio raíz del proyecto):

```
cd exfiltration_agent/
nohup python3 -u control_panel.py > control_panel.log 2>&1 &
```

 * nohup: Evita que el proceso se detenga si se cierra la terminal.
 * python3 -u: Ejecuta Python en modo sin búfer, útil para registros en tiempo real.
 * > control_panel.log 2>&1: Redirige la salida estándar y los errores a control_panel.log para depuración posterior.

 * &: Ejecuta el proceso en segundo plano.
Una vez iniciado, verás mensajes en tu terminal indicando que la aplicación está lista.
Accede a la interfaz a través de tu navegador web en:

```http://127.0.0.1:8050```

Bienvenido a HACKER-SUITE+2000, un kit de herramientas avanzado para operaciones cibernéticas, diseñado para exfiltración de datos, perfilado de sistemas y gestión de cargas útiles, todo a través de una interfaz web intuitiva. Esta herramienta está desarrollada con Python y Dash, ofreciendo una experiencia de usuario fluida para controlar agentes locales o remotos.

---
*🤝 Contribuciones*

**¡Las contribuciones son bienvenidas! Si deseas mejorar hacker-suite+2000, corregir errores o añadir nuevas características, por favor revisa nuestra Guía de Contribución.**

[![Sponsor me on GitHub](https://img.shields.io/badge/Patrocinar-GitHub-brightgreen.svg)](https://github.com/sponsors/karim93160)
[![Buy me a coffee](https://img.shields.io/badge/Donar-Buy%20Me%20A%20Coffee-FFDD00.svg)](https://www.buymeacoffee.com/karim93160)
[![Support me on Ko-fi](https://img.shields.io/badge/Donar-Ko--fi-F16061.svg)](https://ko-fi.com/karim93160)
[![Support me on Patreon](https://img.shields.io/badge/Patreon-Support%20me-FF424D.svg)](https://www.patreon.com/karim93160)
[![Donate on Liberapay](https://img.shields.io/badge/Donar-Liberapay-F6C915.svg)](https://liberapay.com/karim93160/donate)

_________

## Licencia 📜

hacker-suite+2000 se distribuye bajo la [Licencia MIT](https://github.com/Karim93160/hacker-suite-2000/blob/cae8101acb7c14a65792abfcf21b332d1dc8afd0/LICENSE)
_________
## Contacto 📧

Para cualquier pregunta o sugerencia, no dudes en abrir un [issue en GitHub](https://github.com/Karim93160/hacker-suite-2000/issues) o contactarnos por correo electrónico:

[![Contact by Email](https://img.shields.io/badge/Contactar-por%20Email-blue.svg)](mailto:karim9316077185@gmail.com)
_________
<div align="center">
  <h2>🌿 hacker-suite+2000 - Código de Conducta 🌿</h2>
  <p>
    Estamos comprometidos a crear un ambiente acogedor y respetuoso para todos los contribuyentes.
    Por favor tómate un momento para leer nuestro <a href="CODE_OF_CONDUCT.md">Código de Conducta</a>.
    Al participar en este proyecto, aceptas cumplir con sus términos.
  </p>
  <p>
    <a href="CODE_OF_CONDUCT.md">
      <img src="https://img.shields.io/badge/Código%20de%20Conducta-Por%20favor%20Lee-blueviolet?style=for-the-badge&logo=github" alt="Código de Conducta">
    </a>
  </p>
</div>
<div align="center">
  <h2>🐞 Reportar un Error en hacker-suite+2000 🐞</h2>
  <p>
    ¿Encontraste un problema con hacker-suite+2000? ¡Ayúdanos a mejorar el proyecto reportando errores!
    Haz clic en el botón de abajo para abrir directamente un nuevo reporte de error pre-llenado.
  </p>
  <p>
    <a href="https://github.com/karim93160/hacker-suite-2000/issues/new?assignees=&labels=bug&projects=&template=bug_report.md&title=">
      <img src="https://img.shields.io/badge/Reportar%20Error-Abrir%20un%20Issue-red?style=for-the-badge&logo=bugsnag" alt="Reportar un Error">
    </a>
  </p>
</div>

---

## 🎯 Tabla de Contenidos
 * Descripción general
 * Características
 * Estructura del proyecto
 * Requisitos previos
 * Instalación
   * Preparación de Termux (Android)
   * Instalación de dependencias de Python
 * Inicio de la aplicación
 * Uso de la interfaz
   * Pestaña "DYNAMIC DISPLAY"
   * Pestaña "DASHBOARD"
   * Pestaña "AGENT CONTROL"
   * Pestaña "FILE EXPLORER"
   * Pestaña "SYSTEM PROFILER"
   * Pestaña "PAYLOADS & PERSISTENCE"
   * Pestaña "STEALTH & EVASION"
   * Pestaña "LOGS & STATUS"
 * Configuración
 * Contribuciones
 * Licencia
 * Código de conducta
 
 ---
 
# ✨Descripción General
HACKER-SUITE+2000 es un entorno centralizado de operaciones cibernéticas que te permite desplegar, configurar y monitorear un agente de exfiltración. Ya sea que necesites recopilar archivos específicos, obtener información detallada sobre un sistema objetivo, gestionar cargas útiles maliciosas o mantener el sigilo operativo, este conjunto de herramientas te brinda el control necesario a través de una interfaz gráfica basada en navegador web.
Diseñado para ser flexible, soporta exfiltración vía HTTPS y DNS, e incluye mecanismos avanzados de filtrado para apuntar con precisión a los datos. La interfaz ofrece un panel en tiempo real, un explorador de archivos interactivo, capacidades de perfilado de sistemas y controles para sigilo y evasión.

---

## 🛠️ Características
 * Interfaz Web Interactiva: Controla el agente a través de una interfaz de usuario Dash accesible desde cualquier navegador web.
 * Agente de Exfiltración Versátil:
   * Métodos de Exfiltración: Soporta HTTPS (recomendado) y DNS (para escenarios discretos).
   * Filtrado Avanzado: Escaneo de archivos por tipo (inclusión/exclusión), tamaño mínimo/máximo, palabras clave y expresiones regulares.
   * Encriptación AES256: Encripta los datos exfiltrados y los registros para garantizar confidencialidad.
 * Explorador de Archivos Objetivo: Navega por los sistemas de archivos locales o remotos (web) del sistema objetivo, visualiza contenidos de archivos y descarga archivos.
 * Perfilado Detallado del Sistema: Recopila información exhaustiva sobre el sistema objetivo (SO, CPU, memoria, discos, red, usuarios, procesos en ejecución).
 * Gestión de Cargas Útiles: Despliega, ejecuta y elimina cargas útiles personalizadas en el sistema objetivo.
 * Sigilo & Evasión: Opciones para ocultar procesos, anti-debugging y bypass de detección de sandbox.
 * Registros Integrados: Muestra registros del agente en tiempo real y permite leer/descargar registros encriptados.
 * Panel de Estado: Monitorea métricas clave del agente (archivos escaneados, archivos exfiltrados, etc.) en tiempo real.
 * Persistencia de Configuración: Los ajustes se guardan en shared_config.json para fácil recarga.

---

## 📂 Estructura del Proyecto

Aquí tienes una visión general de la organización de archivos y directorios del proyecto:

```
├── CODE_OF_CONDUCT.md
├── LICENSE
├── README.md
├── README_EN.md
├── README_ES.md
├── control_panel.py
├── display
│   ├── index.html
│   ├── script.js
│   └── style.css
├── exf_agent.py
├── modules
│   ├── __pycache__
│   │   ├── aes256.cpython-312.pyc
│   │   ├── file_explorer.cpython-312.pyc
│   │   ├── log_streamer.cpython-312.pyc
│   │   ├── logger.cpython-312.pyc
│   │   ├── system_profiler.cpython-312.pyc
│   │   └── web_explorer.cpython-312.pyc
│   ├── aes256.py
│   ├── anti_evasion.py
│   ├── compression.py
│   ├── config.py
│   ├── exfiltration_dns.py
│   ├── exfiltration_http.py
│   ├── file_explorer.py
│   ├── file_scanner.py
│   ├── log_streamer.py
│   ├── logger.py
│   ├── payload_dropper.py
│   ├── retry_manager.py
│   ├── stealth_mode.py
│   ├── system_profiler.py
│   └── web_explorer.py
├── requirements.txt
├── setup_termux.sh
└── shared_config.json

4 directories, 34 files
```

---

## ⚙️ Requisitos Previos
Asegúrate de tener lo siguiente instalado en tu sistema (recomendado: Linux o Termux para Android):
 * Python 3.x (3.8 o más reciente recomendado)
 * pip (gestor de paquetes de Python)

---

## 🖥️Uso de la Interfaz
La interfaz está organizada en varias pestañas, cada una dedicada a un aspecto específico de la gestión del agente.
Pestaña "DYNAMIC DISPLAY"
Esta pestaña sirve como un panel visual y dinámico, potencialmente para mostrar información agregada o visualizaciones en tiempo real de la actividad del agente. Carga contenido desde display/index.html.
Pestaña "DASHBOARD"
Monitorea el estado del agente en tiempo real.
 * Estadísticas Clave: Muestra número de archivos escaneados, coincidencias encontradas, cantidad de datos exfiltrados, éxito/fallo de exfiltración, estado del agente y marcas de tiempo.
 * Actividad del Sistema en Vivo: Un flujo de registros en tiempo real del agente, dándote información instantánea sobre sus operaciones.
Pestaña "AGENT CONTROL"
Configura los ajustes del agente e inicia/detiene sus operaciones.
 * Despliegue & Configuración:
   * URL Objetivo (HTTPS/DNS): La URL o dirección IP donde se enviarán los datos exfiltrados.
   * Ruta de Escaneo: El directorio local en el sistema objetivo a escanear.
   * Clave AES (32 bytes): Clave de encriptación usada para exfiltración y registros. Requerida.
   * Método de Exfiltración: Elige entre HTTPS (recomendado) o DNS. Si se selecciona DNS, deberás especificar un servidor DNS y dominio.
 * Ajustes de Filtrado: Define criterios para el escaneo de archivos: tipos de archivo a incluir/excluir, tamaño mínimo/máximo, palabras clave y expresiones regulares para buscar en contenidos de archivos.
 * Ajustes Operacionales:
   * URL de Carga Útil (Opcional): URL para descargar una carga útil.
   * Ruta de Carga Útil (Opcional): Ruta donde se guardará la carga útil en el sistema objetivo.
   * Hilos de Procesamiento: Número de hilos a usar para escaneo y subida.
 * Opciones de Depuración & Evasión: Activa modo debug (registros detallados, sin limpieza), desactiva limpieza de rastros o desactiva verificaciones anti-evasivas.
 * Acciones:
   * <kbd>[ GUARDAR TODA LA CONFIG ]</kbd>: Guarda la configuración actual en shared_config.json.
   * <kbd>[ LANZAR AGENTE ]</kbd>: Inicia el agente con la configuración aplicada.
   * <kbd>[ DETENER AGENTE ]</kbd>: Detiene el agente en ejecución.
Pestaña "FILE EXPLORER"
Explora el sistema de archivos del objetivo.
 * Host Objetivo: La URL o dirección IP del objetivo para exploración.
 * Ruta Base: La ruta en el sistema objetivo desde la cual comenzar la exploración (dejar vacío para exploración web completa).
 * Profundidad Máxima: Limita la profundidad de recursión de la exploración.
 * Acciones:
   * <kbd>[ INICIAR EXPLORACIÓN ]</kbd>: Comienza la exploración basada en los parámetros.
   * <kbd>[ DETENER EXPLORACIÓN ]</kbd>: Detiene la exploración en curso.
 * Resultados de Exploración: Muestra archivos y directorios encontrados en una tabla. Puedes "LEER" (ver contenido) o "DESCARGAR" archivos identificados.
 * Registros en Vivo del Explorador: Muestra operaciones del explorador en tiempo real.
Pestaña "SYSTEM PROFILER"
Obtén información detallada sobre el sistema objetivo.
 * <kbd>[ SOLICITAR INFO DEL SISTEMA ]</kbd>: Dispara la recolección de información del sistema desde el agente.
 * Visualización de Información: Los datos se presentan en secciones colapsables:
   * Información del sistema operativo
   * Información de la CPU
   * Uso de memoria
   * Particiones de disco
   * Interfaces de red
   * Usuarios conectados
   * Procesos en ejecución
Pestaña "PAYLOADS & PERSISTENCE"
Gestiona el despliegue y ejecución de cargas útiles.
 * Fuente de Carga Útil (URL): URL desde la cual se descargará la carga útil.
 * Ruta Objetivo en Agente: Ubicación en el sistema objetivo donde se almacenará la carga útil.
 * Acciones:
   * <kbd>[ DESPLEGAR CARGA ÚTIL ]</kbd>: Despliega la carga útil en el objetivo.
   * <kbd>[ EJECUTAR CARGA ÚTIL ]</kbd>: Ejecuta la carga útil desplegada.
   * <kbd>[ ELIMINAR CARGA ÚTIL ]</kbd>: Elimina la carga útil del objetivo.
Pestaña "STEALTH & EVASION"
Configura características de sigilo y anti-evasivas del agente.
 * ACTIVAR OCULTAMIENTO DE PROCESOS: Intenta ocultar el proceso del agente.
 * HABILITAR ANTI-DEBUGGING: Activa mecanismos para detectar y dificultar el debugging.
 * EVITAR DETECCIÓN DE SANDBOX: Activa técnicas para evitar la detección en sandbox.
 * <kbd>[ APLICAR AJUSTES DE SIGILO ]</kbd>: Aplica los ajustes de sigilo seleccionados al agente.
Pestaña "LOGS & STATUS"
Visualiza y gestiona los registros del agente.
 * Flujo de Registros en Vivo del Agente: Una visualización de los registros del agente en tiempo real, similar al panel.
 * Archivo de Registros Encriptados:
   * <kbd>[ ACTUALIZAR REGISTROS ENCRIPTADOS ]</kbd>: Carga y desencripta los registros del agente almacenados localmente (agent_logs.enc). Asegúrate de que la clave AES en la pestaña "AGENT CONTROL" sea correcta para la desencriptación.
   * <kbd>[ DESCARGAR REGISTROS CRUDOS ]</kbd>: Descarga el archivo de registros encriptados (agent_logs.enc).
⚙️ Configuración
El archivo shared_config.json se genera automáticamente (si no existe) al iniciar la aplicación por primera vez. Almacena configuraciones por defecto y la clave AES.
<p align="center">⚠️     ADVERTENCIA     ⚠️</p>
Durante la generación inicial, el campo default_target_url contendrá

```https://webhook.site/YOUR_UNIQUE_URL_HERE```

Es imperativo reemplazar esta URL con la URL de tu propio servicio de recepción de datos (por ejemplo, un webhook.site personalizado) a través de la interfaz o editando manualmente el archivo shared_config.json antes de lanzar el agente.
