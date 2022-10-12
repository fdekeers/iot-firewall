from protocols.Protocol import Protocol

class Application(Protocol):

    # Class variables
    layer = 7             # Protocol OSI layer
    custom_parser = True  # Whether the protocol has a custom parser
