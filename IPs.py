#encoding:utf-8
import struct
import socket
import re

try:
    unicode = unicode
except NameError:
    unicode = str
    
class IPs(object):
    def __init__(self, *args):
        lst_ips = []
        lst_ips_num = []
        for _ in args:
            if isinstance(_, str) or isinstance(_, unicode):
                lst_ips += [_]
            elif isinstance(_, list):
                for II in _:
                    if isinstance(II, str) or isinstance(II, unicode):
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
        ip_range = ip_range.strip()
        start = 0
        end = 0
        if "/" in ip_range:
            #192.168.0.101/29
            ip, mask = ip_range.split("/")
            mask = int(mask)
            if mask<0 or mask>32:
                raise RuntimeError("invalid mask: %d"%mask)
            start= self.ip2int(ip)
            start &= 0xFFFFFFFF<<(32-mask)
            end = start|(0xFFFFFFFF>>mask )
        elif "-" in ip_range:
            start = -1
            end   = -1
            filter = re.compile("^(\d+)\.(\d+)\.(\d+)\.(\d+)-(\d+)\.(\d+)\.(\d+)\.(\d+)$")
            res = filter.findall(ip_range)
            if res and res[0]:
                #192.168.2.97-192.168.2.101
                record = res[0]
                start= self.ip2int( "%s.%s.%s.%s"%(record[0],record[1],record[2],record[3]) )    #如果 res[i] 不在 0~255 之内，ip2int 会报异常。
                end  = self.ip2int( "%s.%s.%s.%s"%(record[4],record[5],record[6],record[7]) )
            else:
                filter = re.compile("^(\d+)\.(\d+)\.(\d+)\.(\d+)-(\d+)$")
                res = filter.findall(ip_range)
                if res and res[0]:
                    #192.168.2.97-101       IP区间
                    record = res[0]
                    start= self.ip2int( "%s.%s.%s.%s"%(record[0],record[1],record[2],record[3]) )
                    end  = self.ip2int( "%s.%s.%s.%s"%(record[0],record[1],record[2],record[4]) )
                else:
                    filter = re.compile("^(\d+)\.(\d+)\.(\d+)-(\d+)$")
                    res = filter.findall(ip_range)
                    if res and res[0]:
                        #192.168.2-4        C类网段区间
                        record = res[0]
                        start= self.ip2int( "%s.%s.%s.0"%(record[0],record[1],record[2]) )
                        end  = self.ip2int( "%s.%s.%s.255"%(record[0],record[1],record[3]) )
                    else:
                        filter = re.compile("^(\d+)\.(\d+)-(\d+)$")
                        res = filter.findall(ip_range)
                        if res and res[0]:
                            #192.1-254      B类网段区间
                            record = res[0]
                            start= self.ip2int( "%s.%s.0.0"%(record[0],record[1]) )
                            end  = self.ip2int( "%s.%s.255.255"%(record[0],record[2]) )
                            
            if start==-1 or end==-1:
                raise RuntimeError("invalid argument: %s"%ip_range)
            
        else:
            #192.168.2.97
            ip=ip_range
            start= self.ip2int(ip)
            end  = self.ip2int(ip)
        
        return (start, end)
    
    def mergeIPs(self, lst):
        def _merge(l, r, log):
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
            

        while 1:
            if len(lst)<=1:
                return lst
            else:
                bMerged = False
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
                            bMerged = True
                            break

                    if bMerged:
                        break
                
                if not bMerged:    #如果没有合并发生，跳出大循环，并返回
                    break
                    
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

        # 两个对象的lst_ips_num都是有序的，把一个往另一个里面插入即可
        lst_a = self.values(type="int")
        len_a = len(lst_a)
        lst_b = other.values(type="int")
        len_b = len(lst_b)

        if 0==len_a:
            return other
        
        if 0==len_b:
            return self

        for r in lst_b:
            A=0
            B=len_a-1
            i=int( (A+B)/2 )
            J=-1      # 没找到，超范围了
            while A<=B:
                if i==0:
                    if r[0]<=lst_a[i][0]:
                        J=i
                        break
                    else:
                        A=i+1
                        i=int( (A+B)/2 )
                elif r[0]>lst_a[i-1][0] and r[0]<=lst_a[i][0]:
                    J=i
                    break
                elif r[0]<=lst_a[i-1][0]:
                    B=i-1
                    i=int( (A+B)/2 )
                elif r[0]>lst_a[i][0]:
                    A=i+1
                    i=int( (A+B)/2 )

            A=0
            B=len_a-1
            i=int( (A+B)/2 )
            K=-1      # 没找到，超范围了
            while A<=B:
                if i==0:
                    if r[1]<=lst_a[i][1]:
                        K=i
                        break
                    else:
                        A=i+1
                        i=int( (A+B)/2 )
                elif r[1]>lst_a[i-1][1] and r[1]<=lst_a[i][1]:
                    K=i
                    break
                elif r[1]<=lst_a[i-1][1]:
                    B=i-1
                    i=int( (A+B)/2 )
                elif r[1]>lst_a[i][1]:
                    A=i+1
                    i=int( (A+B)/2 )


            lst = []
            if J==-1:      ##J==-1, K==-1         #J K, -1 -1, n -1, n n
                lst_a = lst_a+[r]
                len_a = len(lst_a)

            elif K==-1:    #J!=-1, K==-1
                if J==0:
                    lst_a = [r]           #这种情况属于完全覆盖
                    len_a = len(lst_a)
                else:
                    for i in range(0, J-1):   #J-1的前一个 不受影响
                        lst.append(lst_a[i])

                    if r[0]<=lst_a[J-1][1]+1:    #左连 右离
                        t = (lst_a[J-1][0], r[1])
                        lst.append(t)
                    elif r[0]>lst_a[J-1][1]+1:    #左离 右离
                        lst.append(lst_a[J-1])
                        lst.append(r)

                    lst_a = lst
                    len_a = len(lst_a)

            else:          #J!=-1, K!=-1
                if J==0:
                    if r[1]<lst_a[K][0]-1:    #左离 右离
                        lst.append(r)
                        for i in range(K, len_a):
                            lst.append(lst_a[i])

                    elif r[1]>=lst_a[K][0]-1:   #左离 右连 
                        t = (r[0], lst_a[K][1])
                        lst.append(t)
                        for i in range(K+1, len_a):
                            lst.append(lst_a[i])
                            
                    lst_a = lst
                    len_a = len(lst_a)

                else:
                    for i in range(0, J-1):   #J-1的前一个 和 K的后一个不受影响
                        lst.append(lst_a[i])

                    if r[0]<=lst_a[J-1][1]+1 and r[1]<lst_a[K][0]-1:    #左连 右离
                        t = (lst_a[J-1][0], r[1])
                        lst.append(t)
                        for i in range(K, len_a):
                            lst.append(lst_a[i])

                    elif r[0]>lst_a[J-1][1]+1 and r[1]<lst_a[K][0]-1:    #左离 右离
                        lst.append(lst_a[J-1])
                        lst.append(r)
                        for i in range(K, len_a):
                            lst.append(lst_a[i])
                            
                    elif r[0]<=lst_a[J-1][1]+1 and r[1]>=lst_a[K][0]-1:  #左连 右连
                        t = (lst_a[J-1][0], lst_a[K][1])
                        lst.append(t)
                        for i in range(K+1, len_a):
                            lst.append(lst_a[i])
                        
                    elif r[0]>lst_a[J-1][1]+1 and r[1]>=lst_a[K][0]-1:   #左离 右连
                        lst.append(lst_a[J-1])
                        t = (r[0], lst_a[K][1])
                        lst.append(t)
                        for i in range(K+1, len_a):
                            lst.append(lst_a[i])

                    lst_a = lst
                    len_a = len(lst_a)

        obj = IPs()
        obj.lst_ips_num = lst_a
        return obj
        
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

    def hasIP(self, ip):    #使用二分法查找IP
        if not self.lst_ips_num:
            return False

        num = self.ip2int(ip)
        i = 0
        j = len(self.lst_ips_num)-1
        while 1:
            k = int( (i+j)/2 )
            if num<self.lst_ips_num[k][0]:
                j=k-1
            elif num>=self.lst_ips_num[k][0] and num<=self.lst_ips_num[k][1]:
                return True
            elif num>self.lst_ips_num[k][1]:
                i=k+1

            if i>j:
                return False
        
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
        