Virtual Reality
===============

This is a backdoor project for windows operating systems.

## Intended audience

This is a proof-of-concept stealthy backdoor aimed to aid red teams in maintaining
control of their targets during security evaluation process. Project also intends
to expose ways to abuse standard features.

## Features

Extremely stealthy backdoor for Windows platform.

* ICMP-PING backdoor. Passively listens for incoming pings and executes shellcode
delivered in ping payload.
* HTTP backdoor using steganographically encoded images hosted on imgur.com
* Runs on anything from XP to W10

## Details

* Small size by using tinystl and avoiding standard c++ stl
* Cooperative multitasking achieved by using Windows fibers
* All dependencies are permissively licensed
* Permissively licensed, including all dependencies

## Build instructions

### CLion IDE

Compile using MingW compiler toolchain from msys2 distribution from CLion IDE.
It just works.

Compiled artifacts will be found in `cmake-build-*/bin` folder.

### From shell

This is rather involved and messy, but if you absolutely insist on not using CLion:

1. Install [msys2](http://msys2.org/)
2. Install [CMake](https://cmake.org/download/) (one from msys2 repositories wont work)
3. Open cmd.exe and run `cmake -G 'MinGW Makefiles' path/to/source/code`
4. Open msys2 shell and run `mingw32-make`

### Why MinGW?

As you probably have noticed using MinGW on Windows is something of a drama. Reason
for using this compiler is because produced binaries link directly to msvcrt.dll
and run on a very wide range of Windows' versions. Downside is a rahter bumpy
build process, excessive other dependencies and binary size. These issues were
addressed by tweaking compiler parameters and using `tinystl` instead of standard
stl bundled with the compiler. MSVC may produce bit smaller binaries, but making
them run on a very wide array of Windows' versions while linking to msvcrt.dll
is an uphill battle.

## Instructions

Modify `config.h` to suit your needs.

Use `vr.py` to interact with the backdoor.

### Shellcode payload

`vr.py shellcode path/to/shellcode.bin` reads shellcode into script's memory.
On it's own this is useless therefore combine it with other commands. You may
use `-` instead of path in order to read shellcode from `stdin`.

### Ping transport

`msfvenom <...> | vr.py shellcode - -- ping 192.168.0.1` reads a shellcode from
`stdin` and sends it via icmp-ping to `192.168.0.1`. Backdoor running on that
machine will execute this shellcode.

Shellcode will be delivered to the target by sending it as ICMP-PING packet payload.

![ping-demo](https://user-images.githubusercontent.com/19151258/52339219-2c742600-2a15-11e9-95b0-212485421e35.png)

Content of packet appears to be random. The only give-away that something is up
is a rather big packet size, although it is possible to customized packet size
using ping utility or specify custom payload (linux).

### imgur.com transport

`msfvenom <...> | vr.py shellcode - -- png path/to/image.png` reads a shellcode
from `stdin` and encodes into specified `image.png`. This image must exist and
it must be in RGB format (no alpha). Resulting image should be uploaded to
https://imgur.com/ and tagged with one or more tags while one of tags must be
one that is specified in `config.h`.

Shellcode will be encoded into specified image by altering last two bits of
each color component in the target image. 1 byte needs 4 color components
to be encoded and thus requires 1.(3) pixels. Encoded images are indistinguishable
from original to the naked eye. Backdoor queries imgur API for listing images
tagged with a configured tag. Every new image is downloaded and inspected for
encoded payload.

![steg-demo](https://user-images.githubusercontent.com/19151258/52338654-adcab900-2a13-11e9-9887-3a55cde9dc36.png)

Left - original image. Right - image with encoded payload. Bottom - difference mask.
120x75 image was used. As you can see only a tiny portion of pretty small iamge is used
to encode 449 bytes payload.

## Security

Payload is always obfuscated using RC4 algorithm. As you probably have guessed
replay attacks are a thing against this backdoor. Also backdoor may be controlled
by a rival blue team if they have reverse-engineered sample and recovered RC4
key. Utmost security is not the point of this project. If blue team is on to the
backdoor - nothing will save it anyway.

## Recommendations

* If possible - filter out ICMP-PING packets with in firewall
* Take a proactive approach in monitoring your networks. Log everything and
look for abnormalities. Chances are your servers have no business querying
imgur.com or similar social media domains.

## etc

Q: Why this name? This has nothing to do with virtual reality.

A: Nothing at all. And no reason really. Naming is hard.
