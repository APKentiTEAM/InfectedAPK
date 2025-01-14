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

def verificar_programa_linux(programa):
    result_verificar_programas_linux = subprocess.run(["which", programa])
    return result_verificar_programas_linux.returncode == 0

def instalar_dependencias_linux():
    if not verificar_programa_linux("java") or not verificar_programa_linux("curl") or not verificar_programa_linux("msfvenom") or not verificar_programa_linux("git"):
        result_update=subprocess.run(["sudo", "apt-get", "update"])

        if result_update.returncode == 0:
            print("\nUpdate realizado con éxito.\n")

        else:
            print(f"\nError al realizar update:\n")
            sys.exit(1)

    if not verificar_programa_linux("java"):
        print("Instalando Java en Linux...")
        result_install_java = subprocess.run(["sudo", "apt-get", "install", "-y", "default-jre", "default-jdk"])

        if result_install_java.returncode == 0:
            print("\nJava instalado con éxito.\n")

        else:
            print(f"\nError al instalar Java en Linux:\n")
            sys.exit(1)

    if not verificar_programa_linux("curl"):
        print("\nInstalando Curl en Linux...\n")
        result_install_curl = subprocess.run(["sudo", "apt-get", "install", "-y", "curl"])

        if result_install_curl.returncode == 0:
            print("\n Curl instalado con éxito.\n")

        else:
            print(f"\nError al instalar Curl en Linux:\n")
            sys.exit(1)

    if not verificar_programa_linux("msfvenom"):
        print("\nInstalando Metasploit en Linux...\n")
        result_download_metasploit_script = subprocess.run(["curl", "https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb", "-o", "msfinstall"], check=True, capture_output=True, text=True)
        result_change_permissions_msfscript = subprocess.run(["chmod", "755", "msfinstall"])
        result_execute_msfscript = subprocess.run(["./msfinstall"])

        if result_download_metasploit_script.returncode == 0 and result_change_permissions_msfscript.returncode == 0 and result_execute_msfscript.returncode == 0:
            print("\nMetasploit instalado con éxito.\n")

        else:
            print(f"\nError al instalar Metasploit en Linux:\n")
            sys.exit(1)

    if not verificar_programa_linux("git"):
        print("\nInstalando GIT en Linux...\n")
        result_install_git = subprocess.run(["sudo", "apt-get", "install", "-y", "git"])

        if result_install_git.returncode == 0:
            print("\nGIT instalado con éxito.\n")

        else:
            print(f"\nError al instalar GIT en Linux:\n")
            sys.exit(1)

def configureApktool_linux(originRoute, destinantionRoute):
    if not os.path.exists(destinantionRoute):
        print(f"\nCopiando apktool y estableciando permisos...")
        resultCopyApktool = subprocess.run(["cp", originRoute, destinantionRoute])
        resultGivePermissions = subprocess.run(["chmod", "+x", destinantionRoute])

        if resultCopyApktool.returncode == 0 and resultGivePermissions.returncode == 0:
            print("apktool configurado con éxito.")
        else:
            print("Error al configurar apktool.")
            sys.exit(1)

def configureApktoolJar(originRouteJar, destinantionRouteJar):
    if not os.path.exists(destinantionRouteJar):
        print(f"\nCopiando apktool.jar y estableciando permisos...")
        resultCopyApktoolJar = subprocess.run(["cp", originRouteJar, destinantionRouteJar])
        resultGivePermissionsJar = subprocess.run(["chmod", "+x", destinantionRouteJar])

        if resultCopyApktoolJar.returncode == 0 and resultGivePermissionsJar.returncode == 0:
            print("apktool.jar configurado con éxito.")
        else:
            print("Error al configurar apktool.jar")
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

    try:
        if sistema == "posix":
            repoUrl = "https://github.com/APKentiTEAM/InfectedAPK.git"
            rutaDispositivo = "/home/Documents/InfectedAPK"
            clonarRepo(repoUrl, rutaDispositivo)

            instalar_dependencias_linux()

            originRoute = "/home/Documents/InfectedAPK/Tools/apktool"
            destinantionRoute = "/usr/local/bin/apktool"
            configureApktool_linux(originRoute, destinantionRoute)

            originRouteJar = "/home/Documents/InfectedAPK/Tools/apktool.jar"
            destinantionRouteJar = "/usr/local/bin/apktool.jar"
            configureApktoolJar(originRouteJar, destinantionRouteJar)

        elif sistema == "nt":
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
