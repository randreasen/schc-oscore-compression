"""
    Test module for SCHC's Compressor
"""
from SCHC import Compressor

def test___init__():
    '''Tests the compressor's constructor'''
    comp = Compressor.Compressor(None)

    assert not comp.context
    assert "not-sent" in comp.CompressionActions
    assert "value-sent" in comp.CompressionActions
    assert "mapping-sent" in comp.CompressionActions
    assert "LSB" in comp.CompressionActions
    assert "compute-length" in comp.CompressionActions
    assert "compute-checksum" in comp.CompressionActions

def test_ca_notsent():
    """  Tests the compressor's notSent function"""
    comp = Compressor.Compressor(None)
    assert comp.CA_notSent('', '', '', 0, 0, 0) is None

# No length taken into account ?
#def test_CA_valueSent_str():
#    comp = Compressor.Compressor(None)
#    value = '01001'
#    buf = BitBuffer.BitBuffer()
#    comp.CA_valueSent(buf, '', value, 0, 0, 0)
#    assert buf._buf == value

#def test_CA_valueSent_int():
#    comp = Compressor.Compressor(None)
#    buf = BitBuffer.BitBuffer()
#    value = int('1001101', 2)
#    comp.CA_valueSent(buf, b'', value, 4*16, 0, 0)
#    assert buf._buf == value

#def test_CA_mappingSent():
#    comp = Compressor.Compressor(None)
#    TV = [1, 2, 34]
#    FV = 2
#    buf = BitBuffer.BitBuffer()
#    comp.CA_mappingSent(buf, TV, FV, 0, 0, 0)

def test_ca_lsb():
    ''' Tests the compressor's Lest Significant byte's function'''
    assert True

def test_apply():
    """ Tests the Compressor.apply function with actual rules"""
    assert True
