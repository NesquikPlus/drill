from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
from scapy.all import *
import argparse
import struct, pickle, os
from socket import socket, AF_PACKET, SOCK_RAW
from time import sleep
import threading
from random import randint


NUMBER_OF_QUEUE_REGISTERS = 4 #Equal to the number of egress ports

sessionCounter = 0
packetCounter = 0
sessionDict = {}

currentLoad = 0 #Current load of the server to send the newly arrived session packet.
currentPort = 2 #Port of the server to send the newly arrived session packet.

socket1 = None

'''
class RegisterThread(threading.Thread):
   def __init__(self, threadID, name, counter, controller):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.name = name
      self.counter = counter
   def run(self):
      print "Starting " + self.name
      while True:
        controller.read_queue_registers()
      print "Exiting " + self.name
'''

class Controller(object):
    def __init__(self, sw_name):
        self.topo = Topology(db="topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.registers = []
        self.cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))

    def reset_registers(self):#Reset the values of queue size registers
        for i in range(NUMBER_OF_QUEUE_REGISTERS):
            print self.controller.register_reset("queue_lengths", i)

    def read_queue_registers(self):#Read and print queue size registers
        self.queue_registers = []
        for i in range(NUMBER_OF_QUEUE_REGISTERS):
            self.queue_registers.append(self.controller.register_read("queue_lengths", i))
        print self.queue_registers

    def table_add_session(self, srcIP, dstIP, protocol, sport, dport, currentPort):
        #table_add(table_name, action_name, match_keys, action_params=[], prio=None)
        self.controller.table_add("ingressTable", "sessionForward", [srcIP, dstIP, protocol, sport, dport], [str(currentPort)])

    def packet_callback(self, packet):
        global packetCounter, currentLoad, currentPort, socket1

        #currentPort = randint(2, 5)

        packet[Ether].src = "76:66:5e:20:a5:fb"

        srcIP = packet[IP].src
        dstIP =  packet[IP].dst
        protocol = str(packet[IP].proto)

        if(packet[IP].proto == 6 or packet[IP].proto == 17):#TCP, UDP
            packetCounter += 1
            print("Packet " + str(packetCounter) + " Arrived to Control Plane")
            dport =  str(packet[IP].dport)
            sport =  str(packet[IP].sport)

            sessionTuple = (srcIP, dstIP, protocol, dport, sport)

            if(sessionDict.get(sessionTuple) != None): #if session exists
                socket1.send(str(packet)) #simply send the packet if table entry is not added it will come back to CPU
            else:
                sessionDict[sessionTuple] = currentPort # write session to dictionary
                self.table_add_session(srcIP, dstIP, protocol, sport, dport, currentPort) #add table entry to dataplane
                socket1.send(str(packet)) #send the original packet

    def read_registers_loop(self):
        while True:
        	self.read_queue_registers()

    def run_cpu_port_loop(self):
        sniff(iface = "s1-cpu-eth1", filter = "ip and not ether src 76:66:5e:20:a5:fb", prn = self.packet_callback)


if __name__ == "__main__":
    global socket1
    parser = argparse.ArgumentParser()
    parser.add_argument('--sw', type=str, required=False, default="s1")
    args = parser.parse_args()
    socket1 = socket(AF_PACKET, SOCK_RAW)
    socket1.bind(("s1-cpu-eth1", 0))
    controller = Controller(args.sw)
    controller.read_registers_loop()
    #controller.run_cpu_port_loop()
    


