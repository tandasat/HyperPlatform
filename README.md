HyperPlatform
==============

Introduction
-------------
HyperPlatform is an Intel VT-x based hypervisor (a.k.a. virtual machine monitor)
aiming to provide a thin platform for research on Windows. HyperPlatform is
capable of monitoring a wide range of events, including but not limited to,
access to virtual/physical memory and system registers, occurrences of interrupts
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
- https://tandasat.github.io/HyperPlatform/userdocument/
- https://tandasat.github.io/HyperPlatform/doxygen/


Build
------
To build HyperPlatform, the following are required.
- Visual Studio Community 2017 (15.5 or later)
 - https://www.visualstudio.com/downloads/
- Windows Software Development Kit (SDK) for Windows 10 (10.0.10586.0 or later)
 - https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk
- Windows Driver Kit (WDK) 10 (10.0.10586.0 or later)
 - https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit


Installation and Uninstallation
--------------------------------
Clone full source code from Github with a below command and compile it on Visual
Studio.

    $ git clone --recursive https://github.com/tandasat/HyperPlatform.git

On the x64 platform, you have to enable test signing to install the driver.
To do that, open the command prompt with the administrator privilege and type
the following command, and then restart the system to activate the change:

    >bcdedit /set testsigning on

To install and uninstall the driver, use the 'sc' command. For installation:

    >sc create HyperPlatform type= kernel binPath= C:\Users\user\Desktop\HyperPlatform.sys
    >sc start HyperPlatform

Note that the system must support the Intel VT-x and EPT technology to
successfully install the driver. On Windows 10 RS4+ systems, this technology
can automatically be disabled by the Windows kernel which results in the
following error.

    >sc start HyperPlatform
    [SC] StartService FAILED 3224698910:

    A hypervisor feature is not available to the user.

This is due to Windows Defender Credential Guard being enabled by default.
To disable Windows Defender Credential Guard and enable the virtualization
technology for HyperPlatform, follow this instruction.
- https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage

For uninstallation:

    >sc stop HyperPlatform
    >sc delete HyperPlatform
    >bcdedit /deletevalue testsigning

To install the driver on a virtual machine on VMware Workstation, see an "Using
VMware Workstation" section in the HyperPlatform User Document.
- https://tandasat.github.io/HyperPlatform/userdocument/


Output
-------
All logs are printed out to DbgView and saved in C:\Windows\HyperPlatform.log.


Supported Platforms
--------------------
- x86 and x64 Windows 7, 8.1 and 10
- The system must support the Intel VT-x and EPT technology


Related Project(s)
--------------------
- SimpleVisor
 - http://ionescu007.github.io/SimpleVisor/

SimpleVisor is a very (very) simple and readable Windows-specific hypervisor. I
recommend taking a look at the project to learn VT-x if you are new to hypervisor
development. It should give you a clearer view of how a hypervisor is initialized
and executed.

- hvpp
 - https://github.com/wbenny/hvpp
hvpp is a lightweight Intel x64/VT-x hypervisor written in C++. This is about the
same size as HyperPlatform in LOC yet written in a more polished matter with focus
on x64, making the entire code base more readable. This project also addresses
some issues remain unresolved in HyperPlatform and comes with educational comments
and demonstration code to learn VT-x in more depth. Unless you are allergic to C++
or looking for x86 support, I strongly encourage you to study this project too.

- ksm
 - https://github.com/asamy/ksm

ksm is lightweight-ish x64 hypervisor written in C for Windows for Intel
processors. It demonstrates some advanced VT-x features like #VE and VMFUNC where
HyperPlatform does not include.

- Bareflank Hypervisor
 - http://bareflank.github.io/hypervisor/

Bareflank Hypervisor is an actively developed open source hypervisor. It comes
with rich documents, tests, and comments, supports multiple platforms. The size
of code is larger than that of HyperPlatform, but you will find it interesting if
you are looking for more comprehensive yet still lightweight-ish hypervisors.


License
--------
This software is released under the MIT License, see LICENSE.
