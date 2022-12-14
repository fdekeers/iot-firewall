from protocols.ip import ip
from protocols.igmp import igmp

class ipv4(ip):

    # Class variables
    protocol_name = "ipv4"  # Protocol name
    nft_prefix = "ip"       # Prefix for nftables rules

    # Well-known addresses
    addrs = {
        "local": ["192.168.0.0/16", "130.104.96.0/22"],
        "gateway": "192.168.1.1",
        "broadcast": "255.255.255.255",
        "udp-broadcast": "192.168.1.255",
        "igmpv3": "224.0.0.22",
        **igmp.groups
    }
