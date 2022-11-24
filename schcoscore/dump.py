from math import ceil

class MsgDump:
        def __init__(self, msg, compressed=False):
                self.compressed = compressed
                self.msg = msg

        @staticmethod
        def compareNlsb(a,b,N):
                a &= 2**N - 1 
                b &= 2**N - 1

                return a == b


        def compressed_dump(self, payload):
                msg = self.msg.encode()
                print("0x" + msg.hex())

                firstByte = msg[0]
                buf = msg[1:]
                print("0x{:02x} = Rule ID".format(firstByte))
                if payload != b'':
                        found = False

                        p = int(payload.hex(),16)
                        b = int(buf.hex(),16)
                        start = len(payload)*8
                        end = len(buf)*8
                        count = 0
                        for length in range(start,end+1):
                                if self.compareNlsb(p,b,length):
                                        found = True
                                        L = length
                                        break
                                else:
                                        p *= 2
                                        count += 1
                        if not found:
                                print("Could not separate payload from compression residue")
                                return None
                        residue = b >> L
                        p = p >> count
                        res_len = (end-L)/8
                        if int(payload.hex(),16) != p:
                                print("Error substracting payload")
                                return None
                else:
                        residue = int(buf.hex(), 16)
                        res_len = len(buf)
                print("\nCompression residue:")
                print("0b{:0{width}b} ({} bytes)".format(residue, res_len, width=ceil(res_len*8)))
                if payload != b'':
                        print("\nPayload")
                        print("0x{:0{width}x}".format(p, width=len(payload)*2))


        def decompressed_dump(self):
                print("0x" + self.msg.encode().hex())
                print("\nHeader:")
                self.presentFields(*self.get_header())
                print("0x{:04x} = mid".format(self.msg.mid))
                if self.msg.token != b'':
                        print("0x" + self.msg.token.hex() + " = token")
                opt_list = [ x for x in self.msg.opt.option_list()]
                if len(opt_list) > 0:
                        print("\nOptions:")
                        print("0x" + self.msg.opt.encode().hex())
                        for option in opt_list:
                                print("Option {}: {}".format(option.number.numerator, option.number.name))
                                print("Value = {}".format(option.value))

                if self.msg.payload != b'':
                        print("\n0xFF  Payload marker")
                        print("Payload:")
                        print("0x" + self.msg.payload.hex())


        def get_header(self):
                buf = self.msg.encode()
                firstByte = buf[0]
                Ver = "{:02b}".format(firstByte >> 6)
                mtype = "{:02b}".format(self.msg.mtype)
                tkl = "{:04b}".format(firstByte & 0x0f)
                code = "{:08b}".format(self.msg.code.numerator)

                firstByte = "0x" + buf[0:2].hex()
                return [firstByte,[["Ver",Ver], [self.msg.mtype.name,mtype], ["tkl",tkl], [self.msg.code.__repr__()[1:-1],code]]]

        @staticmethod
        def presentFields(title, subfields):
                pos = 0
                print(title)
                for x in subfields:
                        [label, value] = x
                        print("{}{}   {}".format(pos*" ", value, label))
                        pos += len(value)
                print()
