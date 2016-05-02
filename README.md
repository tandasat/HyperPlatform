HyperPlatform
==============

Introduction
-------------
HyperPlatform is an Intel VT-x based hypervisor (a.k.a. virtual machine monitor)
aiming to provide a thin platform for research on Windows. HyperPlatform is
capable of monitoring a wide range of events, including but not limited to,
access to virtual/physical memory and system registers, occurrence of interrupts
and execution of certain instructions.

Researchers are free to selectively enable and/or disable any of those event
monitoring and implement their own logic on the top of HyperPlatform. Some
potential applications are:
- Analyzing kernel mode rootkit
- Implementing virtual-machine-based intrusion prevention system (VIPS)
- Reverse-engineering the Windows kernel

A simplified implementation of those ideas are available:
- MemoryMon detecting execution of kernel memory for rootkit analysis
 - https://github.com/tandasat/MemoryMon
- EopMon spotting a successful elevation of privilege (EoP) exploit
 - https://github.com/tandasat/EopMon
- DdiMon monitoring and controlling kernel API calls with stealth hook using EPT
 - https://github.com/tandasat/DdiMon
- GuardMon observing some of PatchGuard activities
 - https://github.com/tandasat/GuardMon


Advantages
-----------
HyperPlatform is designed to be easy to read and extend by researchers,
especially those who are familiar with Windows. For instance:
- HyperPlatform runs on Windows 7, 8.1 and 10 in both 32 and 64 bit architectures
  without any special configuration (except for enabling Intel-VT technology).
- HyperPlatform compiles in Visual Studio and can be debugged though Windbg
  just like a regular software driver.
- Source code of HyperPlatform is written and formatted in existing styles
  (Google C++ Style Guide and clang-format), and well commented.
- HyperPlatform has no dependencies, supports use of STL and is released under
  a relaxed license.

For more details, see the HyperPlatform User Document and Programmer's Reference.
- http://tandasat.github.io/HyperPlatform/userdocument/
- http://tandasat.github.io/HyperPlatform/doxygen/


Build
------
To build HyperPlatform, the following are required.
- Visual Studio Community 2015 Update 1 or 2
 - https://www.visualstudio.com/en-us/news/vs2015-update1-vs.aspx
- Windows Software Development Kit (SDK) for Windows 10
 - https://dev.windows.com/en-us/downloads/windows-10-sdk
- Windows Driver Kit (WDK) 10
 - https://msdn.microsoft.com/en-us/windows/hardware/hh852365.aspx


Installation and Uninstallation
--------------------------------
On the x64 platform, you have to enable test signing to install the driver.
To do that, open the command prompt with the administrator privilege and type
the following command, and then restart the system to activate the change:

    bcdedit /set testsigning on

To install and uninstall the driver, use the 'sc' command. For installation:

    >sc create HyperPlatform type= kernel binPath= C:\Users\user\Desktop\HyperPlatform.sys
    >sc start HyperPlatform

For uninstallation:

    >sc stop HyperPlatform
    >sc delete HyperPlatform
    >bcdedit /deletevalue testsigning


Note that the system must support the Intel VT-x and EPT technology to
successfully install the driver.

To install the driver on a virtual machine on VMware Workstation, see an "Using
VMware Workstation" section in the HyperPlatform User Document.


Output
-------
All logs are printed out to DbgView and saved in C:\Windows\HyperPlatform.log.


Supported Platforms
--------------------
- x86 and x64 Windows 7, 8.1 and 10
- The system must support the Intel VT-x and EPT technology


Related Project(s)
--------------------
SimpleVisor is a very (very) simple and readable Windows-specific hypervisor. If
HyperPlatform is still too large and complicated to learn VT-x for you, I would
recommend to take a look at the project. It should give you a clearer
view of how a hypervisor is initialized and executed.
- http://ionescu007.github.io/SimpleVisor/


License
--------
This software is released under the MIT License, see LICENSE.
