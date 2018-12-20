from IPs import IP
   
ips = IP('192.168.0.101/29')
for _ in ips:
    print(_)
    
print('-'*16)
ips = IP('192.168.0.97-101')
for _ in ips:
    print(_)
    
print('-'*16)
ips = IP('192.168.2.97-192.168.2.101')
for _ in ips:
    print(_)
    
print('-'*16)
ips = IP('192.168.3.0-192.168.3.0')
for _ in ips:
    print(_)