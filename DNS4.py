import sys
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

def count_dns_query_types(pcap_file):
    dns_query_types = {}


    cap = pyshark.FileCapture(pcap_file, only_summaries=False)

    # Parcourir chaque paquet DNS dans la capture
    for pkt in cap:
        if 'DNS' in pkt:
            dns_query_type_num = int(pkt.dns.qry_type)
            dns_query_type_name = dns_types.get(dns_query_type_num, f"Unknown ({dns_query_type_num})")
            if dns_query_type_name not in dns_query_types:
                dns_query_types[dns_query_type_name] = 0
            dns_query_types[dns_query_type_name] += 1


    cap.close()

    return dns_query_types

def plot_dns_query_types(dns_query_types):
    plt.figure(figsize=(10, 6))
    plt.bar(dns_query_types.keys(), dns_query_types.values(), color='skyblue')
    plt.xlabel('DNS Query Types')
    plt.ylabel('Number of Queries')
    plt.title('DNS Query Types Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py pcapng_file")
        sys.exit(1)

    file = sys.argv[1]
    pcap_file = 'Packet/' + file +'.pcapng'
    dns_query_types = count_dns_query_types(pcap_file)
    plot_dns_query_types(dns_query_types)
