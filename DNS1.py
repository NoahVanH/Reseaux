import sys
import pyshark
import matplotlib.pyplot as plt

def count_resolved_domains(pcap_file):
    resolved_domains = {}

    # Ouvrir la capture de fichiers avec pyshark
    cap = pyshark.FileCapture(pcap_file, only_summaries=False)
    #print(len(cap))

    # Parcourir chaque paquet dans la capture
    for pkt in cap:
        if hasattr(pkt, 'dns') and pkt.dns.qry_name:
            domain_name = pkt.dns.qry_name
            #print(domain_name)
            resolved_domains[domain_name] = resolved_domains.get(domain_name, 0) + 1

    # Fermer la capture de fichiers
    cap.close()

    return resolved_domains



def plot_bar_chart(resolved_domains):
    domains = list(resolved_domains.keys())
    counts = list(resolved_domains.values())

    plt.figure(figsize=(10, 6))
    plt.barh(domains, counts, color='darkblue')  # barres horizontales
    plt.ylabel('Domain Names') 
    plt.xlabel('Number of Resolutions')
    plt.title('Resolved Domains in Packet Capture')
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py pcapng_file")
        sys.exit(1)

    file = sys.argv[1]
    pcap_file = 'Packet/' + file +'.pcapng'   # chemin fichier de capture
    # DNS 1
    resolved_domains = count_resolved_domains(pcap_file)
    plot_bar_chart(resolved_domains)
