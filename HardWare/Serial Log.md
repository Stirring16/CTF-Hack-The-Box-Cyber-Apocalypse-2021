

![image](https://user-images.githubusercontent.com/62060867/116144310-63be7280-a706-11eb-90bd-b6538eee3532.png)

[hw_serial_logs.zip](https://github.com/Stirring16/CTF-Hack-The-Box-Cyber-Apocalypse-2021/files/6379935/hw_serial_logs.zip)


### Ngoài Reverse Engineer, Forensics nay mình kiếm thêm niềm vui mới với duy nhất 1 bài Hardware kk 🏩

* Đầu tiên thử thách này cho ta một file `.SAL`. Thử search xem file mày là gì.

![image](https://user-images.githubusercontent.com/62060867/116147579-1d6b1280-a70a-11eb-911f-5644c89b90fc.png)

* Sau khi tìm kiếm mình thấy được một trang nói về file này `https://www.saleae.com/`
* Để chạy được file này ta cần install phần mềm [logic2](https://support.saleae.com/logic-software/sw-installation)

![image](https://user-images.githubusercontent.com/62060867/116148415-11cc1b80-a70b-11eb-9687-1b11f89454ee.png)

* Haha đầu tiên nhìn trông giống mã vạch mình đi quét thử. Trông thật silly 😔
* Sau khi nghịch phá và research ở đây cả tối, mình phát hiện đây trông giống tín hiệu truyền gì dó được gọi là `baud rate`. 
* Ở thanh công cụ ta có `Async Serial` có thể thay đổi các value

![image](https://user-images.githubusercontent.com/62060867/116150974-3b3a7680-a70e-11eb-8417-c6a95d80ec38.png)

* Chúng ta còn có cửa sổ Terminal

![image](https://user-images.githubusercontent.com/62060867/116151012-47263880-a70e-11eb-9e80-aabe5a446af6.png)

* Mình đã thử thay đổi các giá trị `Bit Rate` và ở Terminal xuất ra các thông báo khác nhau và có result hiển thị

![image](https://user-images.githubusercontent.com/62060867/116152275-e5ff6480-a70f-11eb-8a51-3dfd9754d392.png)


* Vậy thì theo như mình đoán chỉ cần nhập đúng giá trị `Bit Rate` thì flag sẽ xuất hiện
* Mình đã thử tính toán giá trị `baud rate`

![image](https://user-images.githubusercontent.com/62060867/116150282-5d7fc480-a70d-11eb-889e-8e19a74acd30.png)

* Theo như hình trên ta có khoảng cách truyền nhỏ nhất giữa 2 giá tri là  `8,48 bits/us`
* Vậy nếu truyền 1bit/s thì sẽ có kết quả là:  `117,924.5283018868b bits/s`

![image](https://user-images.githubusercontent.com/62060867/116154272-a8500b00-a712-11eb-99c9-97f5c7dc9210.png)

* Sau khi thay đổi giá trị này, mình phát hiện khoảng cách truyền nhỏ nhất giữa 2 trị bị thay đổi lên `13.48us`

![image](https://user-images.githubusercontent.com/62060867/116154543-fb29c280-a712-11eb-8288-5cac8194eb05.png)

* Tiếp tục ta có `7,418.39762611276 bits/s`

![image](https://user-images.githubusercontent.com/62060867/116154830-683d5800-a713-11eb-94b3-a68175f1c704.png)

* Có ai thấy gì không 🕵️ Mình không thấy gì cả. 


