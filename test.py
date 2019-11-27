from IPs import IPs
from IPs import MultiIPs

ips = IPs("192.168.0.101/29")
print(ips)
for _ in ips:
    print(_)
print(len(ips))
print(ips.isIncluded("192.168.0.101"))

print("-"*16)
ips = IPs("192.168.0.97-101")
for _ in ips:
    print(_)
print(len(ips))

print("-"*16)
ips = IPs("192.168.2.97-192.168.2.101")
for _ in ips:
    print(_)
print(len(ips))

print("-"*16)
ips = IPs("192.168.3.1-192.168.3.1")
for _ in ips:
    print(_)
print(len(ips))

print("-"*16)
lst = ["192.168.0.101/29", "192.168.1.101/29", "192.168.2.101-103", "192.168.3.97-192.168.3.101"]
ips = MultiIPs(lst)
for _ in ips:
    print(_)
    
print("-"*16)
lst = ["192.168.1.3-10", "192.168.0.1-9", "192.168.2.2"]
ips = MultiIPs(lst)
for _ in ips:
    print(_)
print(ips)
print(len(ips))
print(ips.isIncluded("192.168.1.3"))

print("-"*16)
lst = ["192.168.1.1-5", "192.168.0.8-9", "192.168.2.2"]
ips = MultiIPs(lst)
for _ in ips:
    print(_)

lst2 = ["192.168.1.1-3", "192.168.1.4-5", "192.168.0.8-9", "192.168.2.2"]
ips2 = MultiIPs(lst2)
print("----")
for _ in ips2:
    print(_)

print("ips==ips2 : %s"%(ips==ips2))
