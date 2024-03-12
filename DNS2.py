import pyshark
import matplotlib.pyplot as plt

def analyze_authoritative_servers(pcap_file):
    authoritative_servers = {}

    # Ouvrir la capture de fichiers avec pyshark
    cap = pyshark.FileCapture(pcap_file, only_summaries=False)
    # Parcourir chaque paquet DNS dans la capture
    for pkt in cap:
        if 'DNS' in pkt and hasattr(pkt.dns, 'ns'):
            domain_name = pkt.dns.qry_name
            ns_servers = pkt.dns.ns.split(',')
            pkt_number = pkt.number
            if domain_name not in authoritative_servers:
                authoritative_servers[domain_name] = []
            
            authoritative_servers[domain_name].append((pkt_number, ns_servers))

    # Fermer la capture de fichiers
    cap.close()

    return authoritative_servers

def plot_authoritative_servers(authoritative_servers):
    for domain_name, ns_info_list in authoritative_servers.items():
        print(f"Domain Name: {domain_name}")
        print("Packet Numbers and Corresponding NS Servers:")
        for pkt_number, ns_servers in ns_info_list:
            print(f"Packet Number: {pkt_number}, NS Servers: {ns_servers}")

if __name__ == "__main__":
    pcap_file = 'Packet/EmptyFolder/empty1.pcapng'  # Remplacer par le chemin de votre fichier de capture
    authoritative_servers = analyze_authoritative_servers(pcap_file)
    plot_authoritative_servers(authoritative_servers)
