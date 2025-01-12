# APK Modification and Payload Injection Script

Este script automatiza el proceso de modificación de APKs Android, incluyendo la clonación de un repositorio, la descompilación de un APK, la inyección de un payload malicioso, y la recompilación y firma del APK modificado.

## Descripción

El script realiza una serie de pasos para modificar un archivo APK, agregarle un payload malicioso generado con `msfvenom`, y luego recompilar y firmar el APK modificado para su distribución. A continuación se describe el flujo general del proceso:

1. **Clonación de Repositorio**: Clona un repositorio que contiene las herramientas necesarias para trabajar con APKs.
2. **Configuración de `apktool`**: Configura las herramientas necesarias (`apktool` y `apktool.jar`) para la modificación de APKs.
3. **Descompresión y Decompilación de APK**: Descomprime un archivo APK comprimido (ZIP) y luego lo decompila con `apktool`.
4. **Generación de Payload con `msfvenom`**: Genera un payload malicioso (troyano) utilizando `msfvenom`.
5. **Inyección de Payload**: Inyecta el payload generado en el APK de destino.
6. **Recompilación y Firma del APK**: Recompila el APK modificado e lo firma para su instalación.
7. **Servidor HTTP Local**: Levanta un servidor HTTP para servir el APK firmado.
8. **Uso de Metasploit**: Inicia un handler de Metasploit para gestionar el payload y establecer la conexión con el dispositivo comprometido.

## Requisitos

- **Python 3**: Asegúrate de tener Python 3 instalado.
- **Herramientas Necesarias**:
  - `apktool`: Para decompilar y recompilar APKs.
  - `msfvenom`: Para generar payloads maliciosos.
  - `Java`: Necesario para firmar el APK modificado.
  - `Metasploit`: Para gestionar el payload.
- **Sistema Operativo**: El script está diseñado para funcionar en sistemas basados en Linux, como Kali Linux.
