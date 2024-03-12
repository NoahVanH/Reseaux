import pyshark
import matplotlib.pyplot as plt

# Dictionnaire de types DNS
dns_types = {
    1: "A",
    28: "AAAA",
    18: "AFSDB",
    42: "APL",
    257: "CAA",
    60: "CNDSKEY",
    59: "CDS",
    37: "CERT",
    5: "CNAME",
    62: "CSYNC",
    49: "DHCID",
    32769: "DLV",
    39: "DNAME",
    48: "DNSKEY",
    43: "DS",
    108: "EU148",
    109: "EUI164",
    13: "HINFO",
    55: "HIP",
    65: "HTTPS",
    45: "IPSECKEY",
    25: "KEY",
    36: "KX",
    29: "LOC",
    15: "MX",
    35: "NAPTR",
    2: "NS",
    47: "NSEC",
    50: "NSEC3",
    51: "NSEC3PARAM",
    61: "OPENPGKEY",
    12: "PTR",
    17: "RP",
    46: "RRSIG",
    24: "SIG",
    53: "SMIMEA",
    6: "SOA",
    33: "SRV",
    44: "SSHFP",
    64: "SVCB",
    32768: "TA",
    249: "TKEY",
    52: "TLSA",
    250: "TSIG",
    16: "TXT",
    256: "URI",
    63: "ZONEMD",
    255: "*",
    252: "AXFR",
    251: "IXFR",
    41: "OPT"
}

def count_resolved_domains(pcap_file):
    resolved_domains = {}

    # Ouvrir la capture de fichiers avec pyshark
    cap = pyshark.FileCapture(pcap_file, only_summaries=False)
    #print(len(cap))

    # Parcourir chaque paquet dans la capture
    for pkt in cap:
        if hasattr(pkt, 'dns') and pkt.dns.qry_name:
            domain_name = pkt.dns.qry_name
            print(domain_name)
            resolved_domains[domain_name] = resolved_domains.get(domain_name, 0) + 1

    # Fermer la capture de fichiers
    cap.close()

    return resolved_domains



def plot_bar_chart(resolved_domains):
    domains = list(resolved_domains.keys())
    counts = list(resolved_domains.values())

    plt.figure(figsize=(10, 6))
    plt.barh(domains, counts, color='darkblue')  # Utilisation de barh() pour créer un diagramme à barres horizontales
    plt.ylabel('Domain Names')  # Modification de l'étiquette de l'axe des ordonnées
    plt.xlabel('Number of Resolutions')
    plt.title('Resolved Domains in Packet Capture')
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    pcap_file = 'Packet/EmptyFolder/empty1.pcapng'  # Remplacer par le chemin de votre fichier de capture
    # DNS 1
    resolved_domains = count_resolved_domains(pcap_file)
    plot_bar_chart(resolved_domains)
