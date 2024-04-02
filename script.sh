#!/bin/bash

# Vérifier argument
if [ $# -eq 0 ]; then
    echo "Usage: bash script.sh monfichier.pcapng"
    exit 1
fi

# Récupérer le nom du fichier
pcap_file="$1"

# Exécuter les trois fichiers Python avec le fichier pcapng en argument

# pcap_file = Folder/fichier SANS l'extension pcapgn
# exemple = EmptyFolder/empty1

python DNS1.py "$pcap_file"

# attention si aucun print dans la console alors aucun NS dans le packet
python DNS2.py "$pcap_file"
python DNS4.py "$pcap_file"

python protocols.py "$pcap_file"
