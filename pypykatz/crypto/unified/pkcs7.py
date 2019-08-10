

# https://gist.github.com/adoc/8550490
def unpad(bytestring, k=16):
    """
    Remove the PKCS#7 padding from a text bytestring.
    """

    val = bytestring[-1]
    if val > k:
        raise ValueError('Input is not padded or padding is corrupt')
    l = len(bytestring) - val
    return bytestring[:l]


## @param bytestring    The text to encode.
## @param k             The padding block size.
# @return bytestring    The padded bytestring.
def pad(bytestring, k=16):
    """
    Pad an input bytestring according to PKCS#7
    
    """
    l = len(bytestring)
    val = k - (l % k)
    return bytestring + bytearray([val] * val)