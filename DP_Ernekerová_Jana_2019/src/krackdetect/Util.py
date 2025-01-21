#!/usr/bin/env python2
#
# detection of key reinstallation attacks
# Copyright (c) 2018, Jana Ernekerova <ernekjan@fit.cvut.cz>
#

import struct
from scapy.layers.dot11 import Dot11, Dot11QoS
from scapy.layers.eap import EAPOL

FLAG_PAIRWISE = 0b0000001000
FLAG_ACK = 0b0010000000
FLAG_SECURE = 0b1000000000


def create_identifier(source, destination, msgNum):
    """ Creates identifier for PairState """
    if msgNum == 1 or msgNum == 3:
        # print ("ID: %s", source + destination)
        return source + destination
    elif msgNum == 2 or msgNum == 4:
        # print ("ID: %s", destination + source)
        return destination + source


def get_sequence_number(p):
        return p[Dot11].SC >> 4


def get_eapol_replay_number(p):
    return struct.unpack(">Q", str(p[EAPOL])[9:17])[0]


def get_eapol_msg_number(p):
    """ According to the flag bits decides which message of the 4-way handshake it is """
    if not EAPOL in p:
        return 0

    keyinfo = str(p[EAPOL])[5:7]
    flags = struct.unpack(">H", keyinfo)[0]
    if flags & FLAG_PAIRWISE:
        # 4-way handshake
        if flags & FLAG_ACK:
            # sent by AP
            if flags & FLAG_SECURE:
                return 3
            else:
                return 1
        else:
            # send by client
            keydatalen = struct.unpack(">H", str(p[EAPOL])[97:99])[0]
            if keydatalen == 0:
                return 4
            else:
                return 2
    return 0

def get_packet_number(p):
    """ Gets packet number from encrypted data frame """
    ivBytes = struct.unpack('>BBB', p[Dot11QoS].original[:3])
    iv = ivBytes[0] * 256 * 256 + ivBytes[1] * 256 + ivBytes[2]
    return iv