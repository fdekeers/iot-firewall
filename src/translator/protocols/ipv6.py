from protocols.ip import ip

class ipv6(ip):

    # Class variables
    protocol_name = "ipv6"  # Protocol name
    nft_prefix = "ip6"      # Prefix for nftables rules

    # Well-known addresses
    addrs = {
        "local": ["fe80::/10", "fc00::/7"],
        "gateway": "fddd:ed18:f05b::1",
        "mdns": "ff02::fb",
        "coap": "ff02::158"
    }
