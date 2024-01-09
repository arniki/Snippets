import sys  


def asn1_len(value_bytes):
    # helper function - should be used in other functions to calculate length octet(s)
    # value_bytes - bytes containing TLV value byte(s)
    # returns length (L) byte(s) for TLV
    n = len(value_bytes)
    if n < 128:
        return bytes([n])
    else:
        length_bytes = []
        while n > 0:
            length_bytes.append(n & 0xff)
            n >>= 8
        length_bytes.reverse()
        length_indicator = bytes([0x80 | len(length_bytes)])
        return length_indicator + bytes(length_bytes)


def asn1_boolean(boolean):
    if boolean:
        boolean = b'\xff'
    else:
        boolean = b'\x00'
    return bytes([0x01]) + asn1_len(boolean) + boolean


def asn1_integer(i):
    # i - arbitrary integer (of type 'int' or 'long')
    # returns DER encoding of INTEGER
    if i == 0:
        return b'\x02\x01\x00'

    bytestring = b''
    while i > 0:
        bytestring = bytes([i & 0xff]) + bytestring
        i >>= 8

    if bytestring[0] & 0x80:
        bytestring = b'\x00' + bytestring
    return b'\x02' + asn1_len(bytestring) + bytestring


def asn1_null():
    # returns DER encoding of NULL
    return b'\x05\x00'


def asn1_bitstring(bitstr):
    # bitstr - string containing bitstring (e.g., "10101")
    # returns DER encoding of BITSTRING
    num_padding_bits = 8 - (len(bitstr) % 8)
    if num_padding_bits == 8:
        num_padding_bits = 0

    value_bytes = []
    byte_value = 0
    bit_count = 0
    for bit in bitstr:
        if bit == '1':
            byte_value |= 1 << (7 - bit_count)
        bit_count += 1
        if bit_count == 8:
            value_bytes.append(byte_value)
            byte_value = 0
            bit_count = 0
    if bit_count != 0:
        value_bytes.append(byte_value)

    return b'\x03' + asn1_len(bytes(value_bytes) + bytes([num_padding_bits])) + bytes([num_padding_bits]) + bytes(value_bytes)


def asn1_octetstring(value_bytes):
    # octets - arbitrary byte string (e.g., b"abc\x01")
    # returns DER encoding of OCTETSTRING
    return bytes([0x04]) + asn1_len(value_bytes) + value_bytes


def asn1_objectidentifier(oid):
    # oid - list of integers representing OID (e.g., [1,2,840,123123])
    # returns DER encoding of OBJECTIDENTIFIER
    oid_bytes = bytes([oid[0] * 40 + oid[1]])
    for i in oid[2:]:
        val_bytes = []
        val_bytes.append(0x80 | (i & 0x7f))
        i >>= 7
        while i > 0:
            val_bytes.append(0x80 | (i & 0x7f))
            i >>= 7
        val_bytes.reverse()
        val_bytes[-1] &= 0x7f
        oid_bytes += bytes(val_bytes)
    return b'\x06' + asn1_len(oid_bytes) + oid_bytes


def asn1_sequence(der_bytes):
    # der - DER bytes to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    return b'\x30' + asn1_len(der_bytes) + der_bytes


def asn1_set(der_bytes):
    # der - DER bytes to encapsulate into set
    # returns DER encoding of SET
    return b'\x31' + asn1_len(der_bytes) + der_bytes


def asn1_utf8string(utf8_bytes):
    # utf8bytes - bytes containing UTF-8 encoded unicode characters (e.g., b"F\xc5\x8d\xc5\x8d")
    # returns DER encoding of UTF8String
    return b'\x0c' + asn1_len(utf8_bytes) + utf8_bytes


def asn1_utctime(time):
    # time - bytes containing timestamp in UTCTime format (e.g., b"121229010100Z")
    # returns DER encoding of UTCTime
    return b'\x17' + asn1_len(time) + time


def asn1_tag_explicit(der, tag):
    # der - DER encoded bytestring
    # tag - tag value to specify in the type octet
    # returns DER encoding of original DER that is encapsulated in tag type

    tag_byte = 0xa0 | (tag & 0x1f)

    return bytes([tag_byte]) + asn1_len(der) + der


# Test
asn1 = asn1_tag_explicit(
    asn1_sequence(
        asn1_set(
            asn1_integer(5) +
            asn1_tag_explicit(asn1_integer(200), 2) +
            asn1_tag_explicit(asn1_integer(65407), 11)
        ) +
        asn1_boolean(True) +
        asn1_bitstring("011") +
        asn1_octetstring(b"\x00\x01\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02") +
        asn1_null() +
        asn1_objectidentifier([1, 2, 840, 113549, 1]) +
        asn1_utf8string(b'hello.') +
        asn1_utctime(b"250223010900Z")), 0)


open(sys.argv[1], 'wb').write(asn1)