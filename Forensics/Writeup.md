> # --- CHALLENGES OF FORENSICS ---

![image](https://user-images.githubusercontent.com/62060867/115960582-6ff6d400-a53c-11eb-9a9f-fabe273fcb67.png)

# 1. Oldest trick in the book
[forensics_oldest_trick.zip](https://github.com/Stirring16/CTF-Hack-The-Box-Cyber-Apocalypse-2021/files/6369734/forensics_oldest_trick.zip)

![image](https://user-images.githubusercontent.com/62060867/115961037-d7ae1e80-a53e-11eb-9d62-c489d5072d23.png)

Challenge này cho mình một file ```PCAP```, đầu tiên hãy analysis

![image](https://user-images.githubusercontent.com/62060867/115961250-d9c4ad00-a53f-11eb-998e-b1101dad7035.png)

So chúng ta có TCP, DNS, ICMP. Sau khi xem sơ lược thì ICMP là trọng tâm cần chú ý đến, Filter ```icmp``` trên wireshark để lọc những thứ không cần thiết 

![image](https://user-images.githubusercontent.com/62060867/115961355-4770d900-a540-11eb-82be-c6e246c3fb56.png)

Tất cả các Protocol ICMP đều có length 100. Look at data, chúng ta có ```PK``` - file zip và chúng repeat 3 lần ```PK```
Sử dụng ```tshark``` để lấy payloads, dùng filter để lấy các packet reply ```ip.dst == 192.168.1.8```

```tshark -r older_trick.pcap -Y "ip.dst == 192.168.1.8" -T fields -e data.data > raw```

Vậy chúng ta đã có được payload, nhưng vấn đề ở đây là làm sao để lấy file zip vì playload ở đây có tận 3 PK, vì vậy mình đã viết một đoạn python để lấy bytes từ vị trí 16 đến 48

![image](https://user-images.githubusercontent.com/62060867/115962768-12b45000-a547-11eb-983e-8ecd011b0824.png)

```
#!usr/bin/env python3
flag = []

with open('raw', 'r') as file:
	text = file.readlines()

for payload in text:
	flag.append(bytearray.fromhex(payload[16:48]))

with open('flag.zip', 'wb') as out_file:
	out_file.write(b''.join(flag))
 ```
 ![image](https://user-images.githubusercontent.com/62060867/115963373-35476880-a549-11eb-90ef-ed738643e739.png)

 So we have a zip file, unzip it
 ```
 ┌──(kali㉿kali)-[~/Desktop/older]
└─$ unzip flag.zip 
Archive:  flag.zip
 extracting: fini/addons.json        
  inflating: fini/addonStartup.json.lz4  
  inflating: fini/broadcast-listeners.json  
  inflating: fini/cert9.db           
  inflating: fini/compatibility.ini  
  inflating: fini/containers.json    
  inflating: fini/content-prefs.sqlite  
  inflating: fini/cookies.sqlite     
  inflating: fini/cookies.sqlite-shm  
  inflating: fini/cookies.sqlite-wal  
  inflating: fini/extension-preferences.json  
  inflating: fini/extensions.json    
  inflating: fini/favicons.sqlite    
  inflating: fini/favicons.sqlite-shm  
  inflating: fini/favicons.sqlite-wal  
  inflating: fini/formhistory.sqlite  
  inflating: fini/handlers.json      
  inflating: fini/key4.db            
  inflating: fini/logins.json        
  inflating: fini/permissions.sqlite  
  inflating: fini/pkcs11.txt         
  inflating: fini/places.sqlite      
  inflating: fini/places.sqlite-shm  
  inflating: fini/places.sqlite-wal  
  inflating: fini/prefs.js           
  inflating: fini/protections.sqlite  
  inflating: fini/search.json.mozlz4  
  inflating: fini/sessionCheckpoints.json  
 extracting: fini/shield-preference-experiments.json  
  inflating: fini/SiteSecurityServiceState.txt  
  inflating: fini/storage.sqlite     
  inflating: fini/times.json         
  inflating: fini/webappsstore.sqlite  
  inflating: fini/webappsstore.sqlite-shm  
  inflating: fini/webappsstore.sqlite-wal  
  inflating: fini/xulstore.json  
 ```
We have: json, sqlite, cookies, db
Đến đây là lúc nhờ đồng đội chơi Web Duytayto.

```
┌──(kali㉿kali)-[~/Desktop/older]
└─$ cd fini      

┌──(kali㉿kali)-[~/Desktop/older/fini]
└─$ sudo apt-get install jq
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
jq is already the newest version (1.6-2.1).
0 upgraded, 0 newly installed, 0 to remove and 394 not upgraded.
                                                        
┌──(kali㉿kali)-[~/Desktop/older/fini]
└─$ jq -r -S '.logins[] | .hostname, .encryptedUsername, .encryptedPassword' logins.json | pwdecrypt -d . -p foobar
https://rabbitmq.makelarid.es
Decrypted: "Frank_B"
Decrypted: "CHTB{long_time_no_s33_icmp}"
 ```
> So we have Flag: CHTB{long_time_no_s33_icmp}



# 2.Key mission	
# 3.Invitation
# 4.AlienPhish
# 5.Low Energy Crypto	
