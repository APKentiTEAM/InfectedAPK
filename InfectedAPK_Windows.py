#!/usr/bin/env python3

import os
import subprocess
import sys
import urllib.request

def clonarRepo(repoUrl, rutaDispositivo):
    if not os.path.exists(rutaDispositivo):
        print(f"\nClonando repositorio {repoUrl} en la ruta {rutaDispositivo}.\n")
        os.makedirs(rutaDispositivo)
        resultClonRepo = subprocess.run(["git", "clone", repoUrl, rutaDispositivo])

        if resultClonRepo.returncode == 0:
            print("\nRepositorio clonado con éxito.\n")
        else:
            print("\nError al clonar el repositorio.\n")
            sys.exit(1)

def verificar_programa_windows(programa):
    result_verificar_programas_windowsx = subprocess.run(["where", programa])
    return result_verificar_programas_windowsx.returncode == 0

def instalar_dependencias_windows():
    if not verificar_programa_windows("java"):
        print("Instalando Java en Windows...")
        result_install_java_windows = subprocess.run(["C:\\InfectedAPK\\dependencies_Windows\\JavaSetup8u431.exe", "/s"])

        if result_install_java_windows.returncode == 0:
            print("\nJava instalado con éxito.\n")

        else:
            print(f"\nError al instalar Java en Windows:\n")
            sys.exit(1)

    if not verificar_programa_windows("git"):
        print("Instalando GIT en Windows...")
        result_install_git_windows = subprocess.run(["C:\\InfectedAPK\\dependencies_Windows\\Git-2.47.1-64-bit.exe", "/VERYSILENT", "/NORESTART"])

        if result_install_git_windows.returncode == 0:
            print("\nGIT instalado con éxito.\n")

        else:
            print(f"\nError al instalar GIT en Windows:\n")
            sys.exit(1)

    if not os.path.exists("C:\\InfectedAPK\\dependencies_Windows\\metasploitframework-latest.msi"):
        print("Instalando Metasploit en Windows...")
        url = "https://windows.metasploit.com/metasploitframework-latest.msi"
        destination = "C:\\InfectedAPK\\dependencies_Windows\\metasploitframework-latest.msi"
        urllib.request.urlretrieve(url, destination)

        result_install_msfvenom = subprocess.run(["msiexec", "/i", "C:\\InfectedAPK\\dependencies_Windows\\metasploitframework-latest.msi", "/quiet", "/norestart"])
        print("Instalación completada con éxito.")

        if result_install_msfvenom.returncode == 0:
            print("\nMsfvenom instalado con éxito.\n")

        else:
            print(f"\nError al instalar Msfvenom en Windows:\n")
            sys.exit(1)

def main():
    sistema = os.name
#INF-57
    try:

        if sistema == "nt":
            repoUrl = "https://github.com/APKentiTEAM/InfectedAPK.git"
            rutaDispositivo = "C:\\InfectedAPK"
            clonarRepo(repoUrl, rutaDispositivo)

            instalar_dependencias_windows()

        else:
            print(f"El sistema operativo {sistema} no es compatible.")
            sys.exit(1)

    except Exception as error:
        print(f"Error: {error}")
        sys.exit(1)

if __name__ == "__main__":
    main()
