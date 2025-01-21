#!/usr/bin/env python2
#
# detection of key reinstallation attacks
# Copyright (c) 2018, Jana Ernekerova <ernekjan@fit.cvut.cz>
#

from Logger import *
from scapy.all import *
from scapy.layers.dot11 import *
from NetworkMonitor import NetworkMonitor
from ListenSocket import ListenSocket
from Util import *
from PairState import PairState
from threading import Thread, Lock
import sys, argparse, atexit, select

WEP = 0x40
DATA_TYPE = 2

# attack to nexus 5
DEMO_MAC_ADDRESS_CLIENT = 'f8:a9:d0:82:75:f2' # debug: for output filtering


class Detector():
    """ Starts the monitoring, handles incoming data, creates pcap """

    def __init__(self, interface, channel, dump=None):
        NetworkMonitor.turn_network_manager_down()
        self.pairs = {}
        log(DEBUG, "Setting up interface: %s on channel %d" % (interface, channel))
        self.monitor = NetworkMonitor(channel, interface, dump=dump)
        self.monitor.start_monitoring()
        self.pcap = None
        if dump:
            self.pcap = PcapWriter("%s.%s.pcap" % (dump, interface), append=False, sync=True)

        log(DEBUG, "Monitoring started", color="green")
        sniff(count=0,
              lfilter=lambda p: EAPOL in p or (p[Dot11].type == 0x02),
              prn=self.handle_received_frame,
              iface=self.monitor.iface_mon)

    def handle_EAPOL(self, p, source, destination):
        """ Handles EAPOL frame """
        msgNum = get_eapol_msg_number(p)
        if msgNum != 0:  # it is 4-way handshake
            pairIdentifier = create_identifier(source, destination, msgNum)
            if pairIdentifier not in self.pairs:
                if msgNum == 1:  # first message and the pair is not saved
                    self.pairs[pairIdentifier] = PairState(destination, source, p)
                else:  # starts with another message (interference)
                    self.pairs[pairIdentifier] = PairState(destination, source, p, msgNum)
            self.pairs[pairIdentifier].handle_msg(msgNum, p)
            log(INFO, "EAPOL-Msg%d(seq=%d,replay=%d)"
                % (get_eapol_msg_number(p), get_sequence_number(p), get_eapol_replay_number(p)))
        else:
            return repr(p)

    def handle_encrypted_data(self, p, source, destination):
        """ Handles encrypted data frame """

        current_packet_number = get_packet_number(p)

        # pair identifier depends on communication direction
        pairIdentifier_1 = source + destination
        pairIdentifier_2 = destination + source
        pair = None

        if pairIdentifier_1 in self.pairs and source == self.pairs[pairIdentifier_1].macaddrClient:
            pair = self.pairs[pairIdentifier_1]
        elif pairIdentifier_2 in self.pairs and source == self.pairs[pairIdentifier_2].macaddrClient:
            pair = self.pairs[pairIdentifier_2]

        # if pair already exists
        if pair is not None:
            # last frame was eapol &&
            if EAPOL in pair.last_packet \
                    and current_packet_number <= pair.packet_number:
                log(DEBUG, "Found data message with IV %s for client %s" % (current_packet_number, pair.macaddrClient))
                if pair.current_s_nonce in pair.used_s_nonce:
                    log(ERROR, "Client %s UNDER ATTACK! Reinstalled nonce %s twice"
                        % (pair.macaddrClient, pair.current_s_nonce.encode('hex')))
            elif EAPOL not in pair.last_packet \
                    and pair.packet_number > current_packet_number \
                    and current_packet_number == 1:
                log(ERROR, "Client %s UNDER ATTACK! Reinstalled nonce %s twice (IV=%d, seq=%d)"
                    % (pair.macaddrClient, pair.current_s_nonce.encode('hex'), current_packet_number, get_sequence_number(p)))
            pair.packet_number = current_packet_number
            pair.last_packet = p

            # output filtering for demo
            if pair.macaddrClient == DEMO_MAC_ADDRESS_CLIENT:
                log(INFO, "Data (IV=%d, seq=%d)" % (current_packet_number, get_sequence_number(p)))

    def handle_received_frame(self, p):
        """ Handles received frame """
        if self.pcap: # writes to pcap file
            self.pcap.write(p)
        if p is None:
            return # no relevant frame

        source = p.addr2
        destination = p.addr1

        # frame type
        if p.type == DATA_TYPE and EAPOL in p:
            # if frame is EAPOL
            return self.handle_EAPOL(p, source, destination)
        elif p[Dot11].FCfield & WEP and Dot11QoS in p:
            # frame is encrypted data
            return self.handle_encrypted_data(p, source, destination)

    def stop(self):
        print "Cleaning up..."
        NetworkMonitor.turn_network_manager_up()

if __name__ == "__main__":
    description = """\
        Detection of Key Reinstallation Attacks (KRACKs)\
    """

    parser = argparse.ArgumentParser(description=description)

    # Required parameters
    parser.add_argument('-i', '--interface', type=str, nargs='+',
                        help='interfaces for monitoring the network', required=True)

    parser.add_argument('-ch', '--channel', type=int, nargs='+',
                        help='channel at which the traffic will be monitored', required=True)

    # Optional parameters
    parser.add_argument('-d', '--dump', type=str, required=False, default=None,
                        help='dumps captured data to .pcap file')
    parser.add_argument('-q', nargs='?', required=False, const=True, default=False,
                        help='quiet')

    args = parser.parse_args()

    if not args.q:
        print "\n\t =======[ KRACK Attack(s) detection ]======\n"

    # Creates subprocesses for more channels and interfaces
    if len(args.interface) > 1:
        threads = []
        i = 0
        for interface in args.interface:
            p = subprocess.Popen(["./krackdetect.py", '-q', "-i", interface, "-ch", str(args.channel[i])])
            thread = Thread(target=p.communicate, args=())
            threads += [thread]
            thread.isDaemon = True
            thread.start()
            i = i + 1
        for x in threads: 
            x.join()
    else:
        detector = Detector(args.interface[0], args.channel[0], args.dump)
        atexit.register(detector.stop)
        
    # ./krackdetect.py -i wlan0 wlan1 wlan2 -ch ch1 ch2 ch3