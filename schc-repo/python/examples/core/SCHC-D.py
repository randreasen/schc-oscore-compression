import os
import sys
sys.path.insert(0, '../..')

import getopt
from flask import Flask
from flask import request
from flask import Response
import base64
import pprint
import json
import binascii

# ----- Flask ------

app = Flask(__name__)
app.debug = True

# -----   SCHC ------


from SCHC.RuleMngt import RuleManager
from SCHC.Parser import Parser
from SCHC.Compressor import Compressor
from SCHC.Decompressor import Decompressor

import SCHC_RULES

# ----- scapy -----

from scapy.all import *
import scapy.contrib.coap

import ipaddress

@app.route('/lns', methods=['GET', 'POST'])
def get_from_LNS():

    print ('here')
    global RM
    
    #fromGW = request.get_json(force=True)

    print ('aqui')
    fromGW = { "data" : "AhUEMhMkNAADDpw="}

    print (fromGW)
    
    if "data" in fromGW:
        print (fromGW)
        payload = base64.b64decode(fromGW["data"])
        print (payload)

        ruleId = payload[0:1]
        SCHCpacket = payload[1:]

        print ("rule ID =", ruleId, "rest = ", SCHCpacket)
        decRule = RM.FindRuleFromID(ruleId[0] )
        if decRule:
            header = bytearray(b"")
            data   = bytearray(b"")
            
            print(decRule)
            header, data = decompressor.apply(SCHCpacket, decRule, "up")
            print ("Header=", binascii.hexlify(header));
            print ("data = ", data);

            fields, empty = packetParser.parser(header)
            print (fields)
            
            
            IPv6Src = (fields[('IPv6.prefixES', 1)][0]<<64) + fields[('IPv6.iidES', 1)][0]
            IPv6Dst = (fields[('IPv6.prefixLA', 1)][0]<<64) + fields[('IPv6.iidLA', 1)][0]

            IPv6Sstr = ipaddress.IPv6Address(IPv6Src)
            IPv6Dstr = ipaddress.IPv6Address(IPv6Dst)

            print ("source address", IPv6Sstr)
            
            IPv6Header = IPv6 (
                version= fields[('IPv6.version', 1)][0],
                tc     = fields[('IPv6.trafficClass', 1)][0],
                fl     = fields[('IPv6.flowLabel', 1)][0],
                nh     = fields[('IPv6.nextHeader', 1)][0],
                hlim   = fields[('IPv6.hopLimit', 1)][0],
                src=IPv6Sstr.compressed, 
                dst=IPv6Dstr.compressed) # / \

            UDPHeader = UDP(
                sport = fields[('UDP.PortLA', 1)][0],
                dport = fields[('UDP.PortLA', 1)][0]
            )

            afterUDP = header[48:]
            print ("after UDP=", binascii.hexlify(afterUDP))
            #CoAPHeader = scapy.contrib.coap.CoAP(afterUDP)
            # IPv6 (
            #     #version = fields[('IPv6.version', 1)][0]
            # )
            CoAPHeader = Raw(load=bytes(afterUDP))
            ls(CoAPHeader)
            print (binascii.hexlify(header[48:]))
                       
            ls(CoAPHeader)

            

            send(IPv6Header/UDPHeader/CoAPHeader, iface="he-ipv6")

        rep_str = "pleased to meet you "
        
        b64_rep = str(base64.b64encode(bytes(rep_str, 'utf-8')))
        b64_rep = b64_rep[2:-1] #remove b and quotes
#        answer = {
#          "fport" : 2,
#          "devEUI": fromGW["devEUI"]#,
#          #"data"  : b64_rep
#        }

        response = app.response_class(
#           response=json.dumps(answer),
            status=200,
            mimetype="application/json"
            )

        return response

    
if __name__ == '__main__':

    print (sys.argv)

    defPort=7002
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hp:",["port="])
    except getopt.GetoptError:
        print ("{0} -p <port> -h".format(sys.argv[0]))
        sys.exit(2)
        
    for opt, arg in opts:
        if opt == '-h':
            print ("{0} -p <port> -h".format(sys.argv[0]))
            sys.exit()
        elif opt in ("-p", "--port"):
            defPort = int(arg)

    RM = RuleManager()
    RM.addRule(SCHC_RULES.rule_coap0)
    RM.addRule(SCHC_RULES.rule_coap1)
    RM.addRule(SCHC_RULES.rule_coap2)

    decompressor = Decompressor (RM)
    packetParser = Parser()

    app.run(host="0.0.0.0", port=defPort)
