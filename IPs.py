import struct
import socket
import re
        
class IPs(object):
    def __init__(self, *args):
        lst_ips = []
        lst_ips_num = []
        for _ in args:
            if isinstance(_, str):
                lst_ips += [_]
            elif isinstance(_, list):
                for II in _:
                    if isinstance(II, str):
                        lst_ips += [II]
                    elif isinstance(II, tuple):
                        lst_ips_num += [II]
                    elif isinstance(II, IPs):
                        lst_ips_num += II.values(type="int")
                    else:
                        raise RuntimeError("init error, not supported args: %s"%II)
            elif isinstance(_, IPs):
                lst_ips_num += _.values(type="int")
            else:
                raise RuntimeError("init error, not supported args: %s"%_)
                
        lst = []
        for _ in lst_ips:
            (start, end) = self.parseIpRange2IntRange(_)
            if start<=end:
                lst += [(start, end)]  # [(ip_num0, ip_num1), ...]
        
        lst += lst_ips_num
        lst = self.mergeIPs(lst)
        self.lst_ips_num = sorted(lst, key=lambda x: x[0])
        self.lsti = 0
        self.ipi = -1
        
    def parseIpRange2IntRange(self, ip_range):
        start = 0
        end = 0
        if "/" in ip_range:
            #192.168.0.101/29
            ip, mask = ip_range.split("/")
            mask = int(mask)
            start= self.ip2int(ip)
            start &= 0xFFFFFFFF<<(32-mask)
            end = start|(0xFFFFFFFF>>mask )
        elif "-" in ip_range:
            ip,max_ipd = ip_range.split("-")
            if "." not in max_ipd:
                #192.168.0.97-101
                max_ipd = int(max_ipd)
                start=self.ip2int(ip)
                end  = (start&0xFFFFFF00)|max_ipd
            else:
                #192.168.2.97-192.168.2.101
                start= self.ip2int(ip)
                end  = self.ip2int(max_ipd)
        else:
            #192.168.2.97
            ip=ip_range
            start= self.ip2int(ip)
            end  = self.ip2int(ip)
        
        return (start, end)
    
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
                log["ret"] = (l[0], r[1])
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
            
    def values(self, type="str"):
        lst = []
        if "str"==type:
            for _ in self.lst_ips_num:
                lst += ["%s-%s"%(self.int2ip(_[0]), self.int2ip(_[1]))]
        elif "int"==type:
            lst = self.lst_ips_num[:]
        return lst
        
    def __str__(self):
        return "\n".join(self.values())
        
    def __len__(self):
        num = 0
        for _ in self.lst_ips_num:
            num += _[1]-_[0]+1
        return num
        
    def __eq__(self, other):  # ==
        other = IPs(other)
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
        
    def __or__(self, other):  # |
        other = IPs(other)
        lst_ips_num = self.values(type="int")
        lst_ips_num += other.values(type="int")
        lst = self.mergeIPs(lst_ips_num)
        lst_ips_num = sorted(lst, key=lambda x: x[0])
        return IPs(lst_ips_num)
        
    def __and__(self, other):  # &
        other = IPs(other)
        A = self-other
        B = other-self
        return (self|other)-(A|B)
        
    def __sub__(self, other):  # -
        other = IPs(other)
        lst0 = self.values(type="int")
        lst1 = other.values(type="int")
        
        lst = []
        for l in lst0:
            for r in lst1:
                if r[1]<l[0]:                                    # --- .......
                    continue
                elif r[0]<=l[0] and r[1]>=l[0] and r[1]<=l[1]:   #    ---.....
                    (c, d) = (r[1]+1, l[1])
                    if c<=d:
                        l = (c, d)
                    else:
                        l = None
                        break
                elif r[0]>=l[0] and r[1]<=l[1]:                  #     .---...
                    (a, b) = (l[0], r[0]-1)
                    if a<=b:
                        lst += [(a, b)]
                        
                    (c, d) = (r[1]+1, l[1])
                    if c<=d:
                        l = (c, d)
                    else:
                        l = None
                        break
                elif r[0]>=l[0] and r[0]<=l[1] and r[1]>l[1]:    #     .....---
                    (a, b) = (l[0], r[0]-1)
                    if a<=b:
                        lst += [(a, b)]
                    l = None
                    break
                elif r[0]>l[1]:                                  #     .......   ---
                    lst += [(l[0], l[1])]
                    l = None
                    break
                elif r[0]<=l[0] and r[1]>=l[1]:                  #   ----------------
                    l = None
                    break
            
            if l and l[0]<=l[1]:
                lst += [(l[0], l[1])]
                l = None
                    
        return IPs(lst)
        
    def __iter__(self):
        return self
        
    def __next__(self):
        return self.next()
        
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
        
        self.lsti = 0
        self.ipi = -1
        raise StopIteration
        
    def contain(self, *args):
        return (self|IPs(*args))==self
        
    @staticmethod
    def ip2int(ip):
        if IPs.isIPv4(ip):
            return struct.unpack("!I", socket.inet_aton(ip))[0]
        else:
            raise RuntimeError("invalid IPv4: %s"%ip)
    
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
        