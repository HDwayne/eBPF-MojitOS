#!/bin/bash

PACKAGE_LIST="zlib1g-dev libelf-dev libbfd-dev libcap-dev libbpf-dev llvm clang git build-essential"

# URL du dépôt Git à cloner
REPO_URL="https://github.com/libbpf/bpftool"


# URL du dépôt Git à cloner
REPO_DIR="./bpf_tool"

#Mise à jour de la liste de paquets
sudo apt-get update -y

#Tentative d'installation des paquets necessaires
if sudo apt-get install -y $PACKAGE_LIST; then
    echo "Les paquets $PACKAGE_LIST ont bien été installés."
else
    echo "Erreur les paquets $PACKAGE_LIST n'ont pas pu être installés."
    echo "Vérifier si les paquets sont disponible dans vo sources de paquets."
    exit 1
fi

# Exécution de git clone
git clone --recurse-submodules $REPO_URL $REPO_DIR

#Vérifie l'execution de la commande git
if [ $? -eq 0 ]; then
    echo "Le clone de '$REPO_URL' a réussi."
else
    echo "Erreur lors du clone de '$REPO_URL'."
    exit 1
fi

#On se déplace dans le dossier d'installation de libbpf
cd $REPO_DIR/libbpf/src/

#Execution du make
sudo make install

#Vérifie l'execution du make
if [ $? -eq 0 ]; then
    echo "Make libbpf a réussi."
else
    echo "Make libbpf a échoué."
    exit 1
fi

#On se déplace dans le dossier d'installation de bpftool
cd ../../src/


#Execution du make
sudo make install

#Vérifie l'execution du make
if [ $? -eq 0 ]; then
    echo "Make bpftool a réussi."
else
    echo "Make bpftool a échoué."
    exit 1
fi


# Recherche de libbpf.so.1 en excluant le dossier /home
LIBBPF_PATH=$(find / \( -path /home -prune \) -o -name libbpf.so.1 -print -quit 2>/dev/null)

# Vérifie si le fichier a été trouvé
if [ -n "$LIBBPF_PATH" ]; then
    # Extraction du chemin du dossier contenant libbpf.so.1
    LIBBPF_DIR=$(dirname "$LIBBPF_PATH")
    
    # Mise à jour du cache ldconfig
    sudo ldconfig $LIBBPF_DIR
    echo "Le chemin $LIBBPF_DIR a été ajouté à ldconfig."
else
    echo "libbpf.so.1 n'a pas été trouvé hors du dossier /home."
    exit 1
fi

exit 0
