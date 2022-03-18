# Ret2dl_resolve
# Reverse
Thông tin về challenge trên web.
!(challenge_info)[https://github.com/zirami/Root-me/ret2dl_resolve/images/challenge_info.png]
Sử dụng lệnh SCP để kéo file challenge trên web root-me về.
!(pull_challenge)[https://github.com/zirami/Root-me/ret2dl_resolve/images/pull_challenge.png]
Kéo file vừa kéo về máy vào IDA để xem pseudo code.
!(main_func)[https://github.com/zirami/Root-me/ret2dl_resolve/images/main_func.png]

Nhận thấy rằng, trong hàm main chỉ gọi duy nhất 1 hàm read, không thể leak địa chỉ (không có thêm bất kỳ 1 hàm nào có chức năng in ra màn hình), như vậy không thể dùng ret2libc để khai thác được. Chúng ta sẽ dùng kỹ thuật có tên là Ret2dl_resolve để giải quyết challenge này.
# Exploit