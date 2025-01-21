#!/usr/bin/env python2
#
# detection of key reinstallation attacks
# Copyright (c) 2018, Jana Ernekerova <ernekjan@fit.cvut.cz>
#

from Logger import *
import sys, subprocess, atexit
from scapy.data import ETH_P_ALL
from ListenSocket import ListenSocket


class NetworkMonitor:
    """Sets the interface to monitor mode"""
    def __init__(self, channel, interface, dump=None):
        self.channel = channel
        self.interface = interface
        self.iface_mon = interface + "mon"
        self.dumpfile = dump
        atexit.register(self.cleanup)

    def configure_interface_for_monitoring(self):
        """Sets the interface to monitor mode"""
        subprocess.call(["ifconfig", self.interface, "up"], stdout=subprocess.PIPE)
        subprocess.call(["airmon-ng", "check", "kill"], stdout=subprocess.PIPE)
        p = subprocess.Popen("iwconfig", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = p.communicate()
        if self.iface_mon not in out:
            subprocess.call(["airmon-ng", "start", self.interface], stdout=subprocess.PIPE) # adds "mon" to iface name

    def set_interface_to_managed(self):
        """Sets the interface to managed mode"""
        subprocess.call(["airmon-ng", "stop", self.iface_mon], stdout=subprocess.PIPE)
        subprocess.call(["ifconfig", self.interface, "up"], stdout=subprocess.PIPE)

    def set_channel(self, channel):
        """Sets the channel of the monitoring interface"""
        subprocess.check_output(["iw", self.iface_mon, "set", "channel", str(channel)])

    def start_monitoring(self):
        """Sets the interface to monitor mode and creates the socket for listening, starts monitoring"""
        self.configure_interface_for_monitoring()
        self.set_channel(self.channel)
        if self.dumpfile:
            subprocess.Popen(["tcpdump", "-i", self.iface_mon, "-w",
                              self.dumpfile + "_" + self.iface_mon + ".tcpdump.pcap"], stdout=None, stderr=None)
        # return ListenSocket(type=ETH_P_ALL, iface=self.iface_mon, dumpfile=self.dumpfile)
        
    def stop_monitoring(self):
        """Sets the interface back to managed mode and starts the networ-manager"""
        self.set_interface_to_managed()

    def cleanup(self):
        """Cleans up before exit"""
        self.stop_monitoring()

    @staticmethod
    def turn_network_manager_up():
        """Restarts a network-manager service, enables user to re-reach network"""
        try:
            subprocess.check_output("systemctl is-active --quiet network-manager.service")
            subprocess.call(["nmcli", "radio", "wifi", "on"], stdout=subprocess.PIPE)
        except:
            pass 

    @staticmethod
    def turn_network_manager_down():
        """Stop a network-manager service for avoiding interference during monitoring"""
        try:
            subprocess.check_output("systemctl is-active --quiet network-manager.service")
            subprocess.call(["nmcli", "radio", "wifi", "off"], stdout=subprocess.PIPE)
        except:
            pass 
        subprocess.call(["rfkill", "unblock", "wifi"], stdout=subprocess.PIPE)
