#encoding:utf-8
from IPs import IPs
from IPs import IPs

ips = IPs(["192.168.1.11-100"])
print("-"*16)
print("|")
print(ips|"192.168.1.97-110")
print("-"*16)
print("sub")
print(ips-["192.168.1.10-12", "192.168.1.22-22", "192.168.1.33-39", "192.168.1.89-110"])
print("-"*16)
print("&")
print(ips&"192.168.1.97-110")

print("-"*16)
ips = IPs(["192.168.1.1-5", "192.168.0.8-9", "192.168.2.2"], "192.168.2.2-4", IPs("192.168.2.5-8"))
print(ips.contain(["192.168.2.2-4", IPs("192.168.2.5-8")]))
print(ips)
print(ips.values())
print(ips.values(type="int"))
for _ in ips:
    print(_)
    
print(len(ips))

print("-"*16)

ips = IPs("192.168.0.101/29")
print(ips)
for _ in ips:
    print(_)
print(len(ips))
print(ips.contain("192.168.0.101"))

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
ips = IPs(lst)
for _ in ips:
    print(_)
    
print("-"*16)
lst = ["192.168.1.3-10", "192.168.0.1-9", "192.168.2.2"]
ips = IPs(lst)
for _ in ips:
    print(_)
print(ips)
print(len(ips))
print(ips.contain("192.168.1.3"))

print("-"*16)
ips = IPs("192.168.1.1-5")
for _ in ips:
    print(_)

print("----")
ips2 = IPs("192.168.1.1-192.168.1.5")
for _ in ips2:
    print(_)
    
print("ips==ips2 : %s"%(ips==ips2))

print("-"*16)
lst = ["192.168.1.1-5", "192.168.0.8-9", "192.168.2.2"]
ips = IPs(lst)
for _ in ips:
    print(_)

print("----")
lst2 = ["192.168.1.1-3", "192.168.1.4-5", "192.168.0.8-9", "192.168.2.2"]
ips2 = IPs(lst2)
for _ in ips2:
    print(_)

print("ips==ips2 : %s"%(ips==ips2))
