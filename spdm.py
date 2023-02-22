""" Generic SPDM v1.0.0 message format

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  Byte 1                 |         Byte 2        | Byte 3 | Byte 4 |
    |-----------------------------------------------------------------------------------|
    | SPDM Major Version | SPDM Minor Version | Request Reponse Code  | Param1 | Param2 |
    |-----------------------------------------------------------------------------------|
    |                               Payload (0 or more bytes)                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


Copyright (C) Henrique de Carvalho <henriquecarvalho@usp.br | decarv.henrique@gmail.com>
"""

from scapy import packet
from scapy import fields

INVERSE_REQUEST_CODES = {
    0x81: "GET_DIGESTS", # Optional 
    0x82: "GET_CERTIFICATE", # Optional 
    0x83: "CHALLENGE", # Optional 
    0x84: "GET_VERSION", # Required
    0xE0: "GET_MEASUREMENTS", # Optional 
    0xE1: "GET_CAPABILITIES", # Required 
    0xE3: "NEGOTIATE_ALGORITHMS", # Required 
    0xFF: "RESPOND_IF_READY", # Required 
    0xFE: "VENDOR_DEFINED_REQUEST", # Optional 
}

REQUEST_CODES = {
    "GET_DIGESTS": 0x81, # Optional
    "GET_CERTIFICATE": 0x82, # Optional
    "CHALLENGE": 0x83, # Optional
    "GET_VERSION": 0x84, # Required
    "GET_MEASUREMENTS": 0xE0, # Optional
    "GET_CAPABILITIES": 0xE1, # Required
    "NEGOTIATE_ALGORITHMS": 0xE3, # Required
    "RESPOND_IF_READY": 0xFF, # Required
    "VENDOR_DEFINED_REQUEST": 0xFE, # Optional
    "Reserved": [0x80, *list(range(0x85, 0xDF)), 0xE2, *list(range(0xE4, 0xFD))]
}

RESERVED_REQUEST_CODES = [
    0x80, 
    *list(range(0x85, 0xDF)), 
    0xE2, 
    *list(range(0xE4, 0xFD))
]

INVERSE_RESPONSE_CODES = {
    0x01: "DIGESTS", # Optional
    0x02: "CERTIFICATE", # Optional
    0x03: "CHALLENGE_AUTH", # Optional 
    0x04: "VERSION", # Required
    0x60: "MEASUREMENTS", # Optional
    0x61: "CAPABILITIES", # Required
    0x63: "ALGORITHMS", # Required
    0x7E: "VENDOR_DEFINED_RESPONSE", # Optional
    0x7F: "ERROR",
}

RESPONSE_CODES = {
    "DIGESTS": 0x01,
    "CERTIFICATE": 0x02,
    "CHALLENGE_AUTH": 0x03,
    "VERSION": 0x04,
    "MEASUREMENTS": 0x60,
    "CAPABILITIES": 0x61,
    "ALGORITHMS": 0x63,
    "VENDOR_DEFINED_RESPONSE": 0x7e,
    "ERROR": 0x7f,
    "Reserved": [0x00, *list(range(0x05, 0x5F)), 0x62, *list(range(0x64, 0x7D))]
}

RESERVED_RESPONSE_CODES = [
    0x00, 
    *list(range(0x05, 0x5F)), 
    0x62, 
    *list(range(0x64, 0x7D))
]

SPDM_VERSION = 0x10

class SPDMUtil:
    def spdm_major_version(version):
        return version & 0xF0

    def spdm_minor_version(version):
        return version & 0x0F


class SPDMGetVersionMessage(packet.Packet):
    """SPDM Requester GET_VERSION Message

       Requirements:
        - The Requester shall begin the discovery process by sending a
        GET_VERSION request message with major version 0x1

    """

    name = "GET_VERSION"
    fields_desc = [
        fields.XByteField(name="SPDMVersion", default=0x1),
        fields.XByteField(name="RequestResponseCode", default=REQUEST_CODES[name]),
        fields.XByteField(name="Param1", default=0x00), # Reserved
        fields.XByteField(name="Param2", default=0x00), # Reserved
    ]


class SPDMVersionMessage(packet.Packet):
    """SPDM Respondent VERSION Message
    """
    name = "VERSION"
    fields_desc = [
        fields.XByteField(name="SPDMVersion", default=0x10),
        fields.XByteField(name="RequestResponseCode", default=RESPONSE_CODES[name]),
        fields.XByteField(name="Param1", default=None),
        fields.XByteField(name="Param2", default=None),
        fields.XByteField(name="Reserved", default=None),
        fields.FieldLenField(
            name="VersionNumberEntryCount", 
            default=None,
            count_of="VersionNumberEntry",
            adjust=lambda pkt, x: x,
            fmt="B"
        ),
        fields.FieldListField(
            name="VersionNumberEntry",
            field=fields.XShortField("Version", None), # LE
            default=None,
            count_from=lambda pkt: pkt.VersionNumberEntryCount,
        )
    ]


class SPDMGetCapabilitiesMessage(packet.Packet):
    pass

class SPDMCapabilitiesMessage(packet.Packet):
    pass

class SPDMNegotiateAlgorithmsMessage(packet.Packet):
    pass

class SPDMAlgorithmsMessage(packet.Packet):
    pass

class SPDMGetDigestsMessage(packet.Packet):
    pass

class SPDMDigestsMessage(packet.Packet):
    pass


if __name__ == "__main__":
    print("##### DEBUGGING MODE #####")

    # Get Version Packets
    print("Creating packet.")
    get_version_packet = SPDMGetVersionMessage()
    get_version_packet.show()
    print("The raw data of GET_VERSION request message is:", 
          bytes(get_version_packet))

    # Version Packets
    print("Creating packet with raw bytes.")
    byte_string = b"\x10\x04\x00\x00\x00\x02\x10\x00\x12\x00"
    version_packet = SPDMVersionMessage(byte_string)
    version_packet.show()
    print("The raw data of VERSION packet is ", bytes(version_packet))
    assert(byte_string == bytes(version_packet))

    print("Creating packet with arguments.")
    version_packet = SPDMVersionMessage(
        VersionNumberEntryCount=0x02,
        VersionNumberEntry=[0x1000, 0x1200],
    )
    version_packet.show()
    print("The raw data of VERSION packet is ", bytes(version_packet))
