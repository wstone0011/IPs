import struct
import socket

class IP(object):
    ip0 = 0
    ip1 = 0
    ipi = ip0
    bNull = False
    
    def __init__(self, ips):
        try:
            if '/' in ips:
                #192.168.0.101/29
                net_addr,mask = ips.split('/')
                mask = int(mask)
                start, = struct.unpack('!L', socket.inet_aton(net_addr))
                start &= 0xFFFFFFFF << (32-mask)
                end = start | ( 0xFFFFFFFF >> mask )
                self.ip0 = start
                self.ip1 = end
                self.ipi = self.ip0
            elif '-' in ips:
                net_addr,max_ipd = ips.split('-')
                if '.' not in max_ipd:
                    #192.168.0.97-101
                    max_ipd = int(max_ipd)
                    start, = struct.unpack('!L', socket.inet_aton(net_addr))
                    end = ( start & 0xFFFFFF00 ) | max_ipd
                    self.ip0 = start
                    self.ip1 = end
                    self.ipi = self.ip0
                else:
                    #192.168.2.97-192.168.2.101
                    start, = struct.unpack('!L', socket.inet_aton(net_addr))
                    end, = struct.unpack('!L', socket.inet_aton(max_ipd))
                    self.ip0 = start
                    self.ip1 = end
                    self.ipi = self.ip0
            if self.ip0 > self.ip1:
                self.bNull = True
        except Exception as e:
            print(e)
            self.bNull = True
        
    def __iter__(self):
        if self.bNull:
            return None
        else:
            return self
        
    def __next__(self):
        return self.next()
        
    def next(self):  #python2
        if self.ipi >= self.ip0 and self.ipi <= self.ip1:
            val = socket.inet_ntoa(struct.pack('!L', self.ipi))
            self.ipi+=1
            return val
        else:
            raise StopIteration
        