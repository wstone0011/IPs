import struct
import socket
import re

class IPs(object):
    def __init__(self, ips):
        try:
            self.ip0 = 0
            self.ip1 = 0
            self.ipi = self.ip0
            self.bNull = False
            
            if "/" in ips:
                #192.168.0.101/29
                ip, mask = ips.split("/")
                mask = int(mask)
                start= self.ip2int(ip)
                start &= 0xFFFFFFFF<<(32-mask)
                end = start|(0xFFFFFFFF>>mask )
                self.ip0 = start
                self.ip1 = end
                self.ipi = self.ip0
                
            elif "-" in ips:
                ip,max_ipd = ips.split("-")
                if "." not in max_ipd:
                    #192.168.0.97-101
                    max_ipd = int(max_ipd)
                    start=self.ip2int(ip)
                    end  = (start&0xFFFFFF00)|max_ipd
                    self.ip0 = start
                    self.ip1 = end
                    self.ipi = self.ip0
                    
                else:
                    #192.168.2.97-192.168.2.101
                    start= self.ip2int(ip)
                    end  = self.ip2int(max_ipd)
                    self.ip0 = start
                    self.ip1 = end
                    self.ipi = self.ip0
            else:
                #192.168.2.97
                ip=ips
                start= self.ip2int(ip)
                end  = self.ip2int(ip)
                self.ip0 = start
                self.ip1 = end
                self.ipi = self.ip0
                
            if self.ip0 > self.ip1:
                self.bNull = True
                
        except Exception as e:
            print(e)
            self.bNull = True
    
    def __str__(self):
        return "%s-%s"%(self.int2ip(self.ip0), self.int2ip(self.ip1))
        
    def __len__(self):
        if self.bNull:
            return 0
        else:
            return self.ip1-self.ip0+1
            
    def __eq__(self, other):
        if not (isinstance(other, IPs)):
            return False
        
        if self.ip0==other.ip0 and self.ip1==other.ip1:
            return True
        else:
            return False
        
    def __iter__(self):
        return self
        
    def __next__(self):
        return self.next()
        
    def next(self):  #python2
        if self.ipi >= self.ip0 and self.ipi <= self.ip1:
            val = self.int2ip(self.ipi)
            self.ipi+=1
            return val
        else:
            self.ipi = self.ip0
            raise StopIteration
        
    def isIncluded(self, ip):
        ip_num = self.ip2int(ip)
        return ip_num>=self.ip0 and ip_num<=self.ip1
        
    @staticmethod
    def ip2int(ip):
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    
    @staticmethod
    def int2ip(ip_num):
        return socket.inet_ntoa(struct.pack("!I", ip_num))
    
    @staticmethod
    def isIPv4(ip):
        IP_PATTERN = "^((0|[1-9]\d?|[0-1]\d{2}|2[0-4]\d|25[0-5])\.){3}(0|[1-9]\d?|[0-1]\d{2}|2[0-4]\d|25[0-5])$"
        if not ip:
            return False
        filter = re.compile(IP_PATTERN, re.I)
        return True if filter.match(ip.strip()) else False
        
        
class MultiIPs(IPs):
    def __init__(self, lst_ips):
        try:
            self.lst_ips_num = []
            
            lst = []
            for _ in lst_ips:
                m = IPs(_)
                lst.append([m.ip0, m.ip1])
            
            lst = self.mergeIPs(lst)
            self.lst_ips_num = sorted(lst, key=lambda x: x[0])
            self.lsti = 0
            self.ipi = -1
        except Exception as e:
            print(e)
    
    def mergeIPs(self, lst):
        def _merge(l, r, log):
            bFlagMerged = False
            
            if l[0]>r[0]:
                l,r = r,l
                
            if l[1]>=r[1]:
                log["bFlagMerged"] = True
                log["ret"] = l
            elif l[1]+1>=r[0] and l[1]<r[1]:
                log["bFlagMerged"] = True
                log["ret"] = [l[0], r[1]]
            else:
                log["bFlagMerged"] = False
            
        if len(lst)<=1:
            return lst
        else:
            for i in range(0, len(lst)-1):
                l = lst[i]
                for j in range(i+1, len(lst)):
                    r = lst[j]
                    log = {}
                    _merge(l, r, log)
                    if log["bFlagMerged"]:
                        lst.remove(l)
                        lst.remove(r)
                        lst.append(log["ret"])
                        return self.mergeIPs(lst)
                    
            return lst
            
    def __str__(self):
        s = ""
        for _ in self.lst_ips_num:
            s += "%s-%s\n"%(self.int2ip(_[0]), self.int2ip(_[1]))
        return s
        
    def __len__(self):
        num = 0
        for _ in self.lst_ips_num:
            num += _[1]-_[0]+1
        return num
        
    def __eq__(self, other):
        if not (isinstance(other, MultiIPs)):
            return False
            
        if len(self)!=len(other):
            return False
        
        bFlag = True
        for i in range(0, len(self.lst_ips_num)):
            l = self.lst_ips_num[i]
            r = other.lst_ips_num[i]
            if l[0]==r[0] and l[1]==r[1]:
                continue
            else:
                bFlag = False
                break
        
        return bFlag
        
    def next(self):  #python2
        for i in range(self.lsti, len(self.lst_ips_num)):
            lst = self.lst_ips_num[i]
            if self.ipi<lst[0]:
                self.ipi = lst[0]
            
            if self.ipi<=lst[1]:
                val = self.int2ip(self.ipi)
                self.ipi+=1
                if self.ipi>lst[1]:
                    self.lsti += 1
            return val
        
        self.ipi = -1
        raise StopIteration
        
    def isIncluded(self, ip):
        ip_num = self.ip2int(ip)
        bFlag = False
        for _ in self.lst_ips_num:
            if ip_num>=_[0] and ip_num<=_[1]:
                bFlag = True
                break
                
        return bFlag
        