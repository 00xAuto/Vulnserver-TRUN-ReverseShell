# Vulnserver-TRUN-ReverseShell

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

There are alot of ways to fuzz for the offset. What i will use is msf-pattern_create




Vulnserver is a famous binary for studying basic binary exploitation. In this blog, I will be showcasing phase 1 in general vulnserver studies... Being the "TRUN" prefix. This is not considered hard by any means. 
