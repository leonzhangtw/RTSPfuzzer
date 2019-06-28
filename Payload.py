from random import *
from copy import deepcopy
from itertools import islice, product, chain
import string

class Payload():

    def __init__(self):
        self.rtsp_payload_format = {}
        self.rtsp_payload_library()
        # self.rtsppayload = deepcopy(self.rtsp_payload_format)


    def rtsp_payload_library(self):
        self.rtsp_payload_format['header'] = ["","","","",""]
        self.rtsp_payload_format['cseq'] = ["",""]
        self.rtsp_payload_format['auth'] = ["","","","","","",""]
        self.rtsp_payload_format['agent'] = ["",""]
        self.rtsp_payload_format['transport'] = ["", "", "", ""]
        self.rtsp_payload_format['session'] = ["", ""]
        self.rtsp_payload_format['range'] = ["", "", ""]


    """
    random payload generator 
    """
    def random_generator_payload(self,payload,length,debug):
        random_key = choice(payload.keys())
        random_position = randint(0,len(payload[random_key])-1 )
        # print("k:"+random_key+" random_position:",random_position)
        if debug == "Y" :
            print("------------Debug Message Start------------")
            print("Advance Fuzzing Testcase Details:")
            print("Random Payload Key : %s"%(random_key))
            print("Random Payload Position : %s"%(random_position))
            print("Random Payload Size : %s "%(length))
            print("------------Debug Message End------------")
        payload[random_key][random_position] = self.createpattern(payload_length=length)
        return payload
    """
    Specific payload generator
    """
    def specific_generator_payload(self,payload,target_key,length,debug):
        random_position = randint(0,len(payload[target_key])-1 )
        if debug == "Y" :
            print("------------Debug Message Start------------")
            print("Advance Fuzzing Testcase Details:")
            print("Specific Payload Key : %s"%(target_key))
            print("Specific Payload Position : %s"%(random_position))
            print("Specific Payload Size : %s "%(length))
            print("------------Debug Message End------------")

        payload[target_key][random_position] = self.createpattern(payload_length=length)
        return payload


    def createpattern(self,payload_length):
        length = int(payload_length)


        data = ''.join(tuple(islice(chain.from_iterable(product(
            string.ascii_uppercase, string.ascii_lowercase, string.digits)), payload_length)))

        # input(data)
        # data = "A"*200

        return data

# if __name__ == '__main__':
#     test = Payload()
#
#     print(len(test.rtsp_payload_format))
#     print(test.rtsp_payload_format.keys())
#     x = choice(test.rtsp_payload_format.keys())
#     print(x)
#     print(len(test.rtsp_payload_format[x]))
#     number = randint(0,len(test.rtsp_payload_format[x]))
#     test.rtsppayload[x][number] = "aaa"
#     print(test.rtsppayload)
#     print(test.rtsp_payload_format)