from protocols.Protocol import Protocol

class igmp(Protocol):
    
    # Class variables
    protocol_name = "igmp"  # Protocol name
    layer = 3               # Protocol OSI layer
    custom_parser = True    # Whether the protocol has a custom parser

    # Supported keys in YAML profile
    supported_keys = [
        'type',
        'group'
    ]
