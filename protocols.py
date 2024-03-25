import pyshark
import sys
def count_protocols(pcap_file):
    # Ouvrir la capture de fichiers avec pyshark
    cap = pyshark.FileCapture(pcap_file)

    # Initialiser un dictionnaire pour stocker les comptes des protocoles
    protocol_counts = {}

    # Parcourir chaque paquet dans la capture
    for pkt in cap:
        # Vérifier si le paquet contient une couche de protocole
        if hasattr(pkt, 'protocol'):
            protocol = pkt.protocol
            # Incrémenter le compteur pour ce protocole dans le dictionnaire
            if protocol in protocol_counts:
                protocol_counts[protocol] += 1
            else:
                protocol_counts[protocol] = 1

    # Fermer la capture de fichiers
    cap.close()

    return protocol_counts

def display_protocol_counts(protocol_counts):
    print("Protocols and their counts:")
    for protocol, count in protocol_counts.items():
        print(f"{protocol}: {count}")

if __name__ == "__main__":
    file = sys.argv[1]
    pcap_file = 'Packet/' + file +'.pcapng'   # Remplacer par le chemin de votre fichier de capture
    protocol_counts = count_protocols(pcap_file)
    display_protocol_counts(protocol_counts)
