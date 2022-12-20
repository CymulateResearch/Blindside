Blinside

Blindside is a technique for evading the monitoring of endpoint detection and response (EDR) and extended detection and response (XDR) platforms using hardware breakpoints to inject commands and perform unexpected, unwanted, or malicious operations. It involves creating a breakpoint handler, and setting a hardware breakpoint that will force the debugged process to load only ntdll to memory. This will result in a clean and unhooked ntdll which then could be copied to our process and unhook the original ntdll.

![](https://cymulate.com/wp-content/uploads/2022/12/blindside-image-004.png)


Please note that this technique should only be used for research and testing purposes and should not be used for any illegal or malicious activities. This repository contains the necessary code and instructions for implementing the Blindside technique.