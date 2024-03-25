import pyshark
import sys
import pyshark

def count_protocols(pcap_file):
    total_packets = 0
    protocols = {}

    # Ouvrir la capture de fichiers avec pyshark
    cap = pyshark.FileCapture(pcap_file)

    # Compter le nombre total de paquets
    for pkt in cap:
        total_packets += 1

        # Vérifier si le paquet a un attribut 'highest_layer'
        if hasattr(pkt, 'highest_layer'):
            protocol = pkt.highest_layer
            protocols[protocol] = protocols.get(protocol, 0) + 1

    # Fermer la capture de fichiers
    cap.close()

    # Calculer le pourcentage de chaque protocole
    for protocol, count in protocols.items():
        percentage = (count / total_packets) * 100
        protocols[protocol] = percentage

    return protocols

if __name__ == "__main__":
    file = sys.argv[1]
    pcap_file = 'Packet/' + file +'.pcapng' 
    #pcap_file = 'mon_fichier.pcapng'  # Remplacer par le chemin de votre fichier de capture
    protocols = count_protocols(pcap_file)
    for protocol, percentage in protocols.items():
        print(f"{protocol}: {percentage:.2f}%")


