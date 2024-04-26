---
layout: post
title:  "DarkSide Ransomware Analysis"
categories: [Malware-Analysis]
tags: [malware-analysis, windows-security, ransomware ]
---



# DarkSide Ransomware Analysis

## Executive Summary 
The malware is a basic ransomware without any networking functionality. It encrypts the first 0x20000 bytes of the files by xoring them with a value that is generated from a random byte. 
Furthermore, the malware encrypts said random byte using RSA encryption and derives a base64 string from the encrypted value. The encryption key for this is derived from a base64 string that is already present in the malware. The new base64 string that is derived is then stored in a text file that gets created in each directory where the encryption happens.  
The malware also deletes the shadow backup files. Depending on the kernel version, the malware might perform a UAC bypass to achieve this.
The malware also encrypts network resources. However, the malware does not encrypt files within certain directories. 
The IID values used to perform the UAC bypass along with the original base64 string present in the malware are good host-based indicators.



## Basic Static Analysis 

![](/images/Pasted%20image%2020240219213301.png)

According to PE Studio, this is a GUI program.

![](/images/Screenshot%202024-14-02%20151309.png)

The malware was compiled on 10th May, 2019.
Since the entropy is less than 7, the malware is not encrypted. There is also no signature, so the malware is most likely not packed. The virtual size is also not much bigger than the raw size. This is a good indication that the malware is not encrypted or packed. 

![](/images/Pasted%20image%2020240219220520.png)

The text section contains the program code. The rdata section is read-only and contains the import and export information.

![](/images/Pasted%20image%2020240219220746.png)
> rdata section in Ghidra

The data section contains initialized data and global variables. Based on the entropy, it is most likely empty.  
#### Hash Values 
md5,C63567B7A0D7737E683A9A16FA5E5318
sha1, E30E60B8B7C24C202313D35329845361AD2CC4F4
sha256,5DCBF5665EEF93769ABC2E92749C3DEABEA8F0AD1EF2AE946108D5670C620DC9
imphash,D8C7BBCE2769AD454D16B7111F8E5E69

![](/images/Screenshot%202024-14-02%20144737.png)
> Result of entering the hash values into Virus Total

The file also has an invalid checksum.
![](/images/Pasted%20image%2020240219214941.png)

![](/images/Screenshot%202024-14-02%20151425.png)

Based on the imported CryptoAPI functions, it seems that the malware has some kind of encryption functionality. FindNextFileW indicates that the malware might traverse through the file system. VerSetConditionMask might be used by the malware to get the system version. The malware most likely also creates other processes. The WNetEnumResourceW indicates that the malware might also access the shared network resources.  

We also see some suspicious strings present in the malware sample.
![](/images/Pasted%20image%2020240219221249.png)
![](/images/Pasted%20image%2020240219221309.png)

There is a base64 string that stands out. However, decoding the string does not give any useful information. 
There is also a suspicious IID value and a command to delete the shadow backup files.




## Basic Dynamic Analysis

After running the program, we see that most of our files have been encrypted, and there is a "HELP_PC.EZDZ-REMOVE.txt" that gets created in each directory where the files have been encrypted. 

The malware does not import any registry functions, so it most likely does not affect the registry values. This is confirmed by looking at the procmon logs. 
![](/images/Screenshot%202024-19-02%20153153.png)
> The malware does not set any registry values

The malware does read and write to a lot of files.
![](/images/Screenshot%202024-18-02%20220404.png)![](/images/Screenshot%202024-18-02%20220309.png)

For Windows 7 and Windows 10, the malware does not create another process. However, if the kernel version is less than or equal to 5.2, the malware will make a call to CreateProcessW to create a vssadmin.exe process.

The malware does not seem to start any services. 

Not all of the files get encrypted. Files within certain directories such as Windows, Program Files, etc. are untouched by the malware.

As expected, the malware does not display any networking activity.




## Ghidra Analysis 

![](/images/Screenshot%202024-19-02%20172123.png| Check out this amazing picture.)
>Overview of the entry function

![](/images/Screenshot%202024-18-02%20103248.png)
The malware starts by checking if the current process running on the WoW64 emulator.
WoW64 enables 32-bit applications to run on a 64-bit machine.
The second parameter is a boolean value and will be set to True if the malware is running on WoW64 emulator. 

The malware then loads the ntdll library and stores the process address of RtlCreateProcessParametersEx in a global data segment. 

![](/images/Screenshot%202024-18-02%20114731.png)

If the process is running on WoW64 emulator, the malware also stores the NtWow64ReadVirtualMemory64 and NtWow64QueryInformationProcess64 processes in the data segment.

![](/images/Screenshot%202024-18-02%20114747.png)

Looking at the cross-references, it becomes clear that NtWow64QueryInformationProcess64 will be called later in the future. 

![](/images/Screenshot%202024-19-02%20174158.png)
 
If the process is running on the WoW64 emulator, the malware will get its PEB.

![](/images/Screenshot%202024-19-02%20193348.png)

![](/images/Screenshot%202024-19-02%20193333.png)

It will then call a function by passing it the value of the PEB at an offset of 0x20. This is most likely used to acquire a lock to access fields within the PEB.

![](/images/Pasted%20image%2020240219194718.png)
> Source: https://www.travismathison.com/posts/PEB_TEB_TIB-Structure-Offsets/




### Delete Shadows 

Get system information by calling FUN_00401270.
If kernel version is 5.2 or lower this function will return 0, otherwise, it will return 1. 

The malware then goes on to delete the backup copies of the files.
The malware can do this in two different ways based on the kernel version. 

If the function returns zero, the malware will directly delete the shadow backup files by creating a vssadmin.exe process. 

![](/images/Screenshot%202024-18-02%20120017.png)

If the function returns one, the malware will go through some extra steps to delete the backup files.

![](/images/Pasted%20image%2020240219182808.png)

Like before the malware gets its own PEB structure and modifies its contents.
RtlInitUnicodeString initializes a UNICODE_STRING structure to refer to an existing unicode string. Hence, the ImagePathName and the CommandLine string will be set to C:\\Windows\\explorer.exe

Based on the offsets the malware also changes its loader data. 
![](/images/Screenshot%202024-19-02%20182730.png)
> PEB Offset Table 
> Source: https://www.travismathison.com/posts/PEB_TEB_TIB-Structure-Offsets/

![](/images/Pasted%20image%2020240219183020.png)
> PEB_LDR_DATA Offset Table 
> Source: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntpsapi_x/peb_ldr_data.htm

Based on IID values, the malware performs a UAC Bypass using CMSTPLUA COM interface.
> Source: https://gist.github.com/api0cradle/d4aaef39db0d845627d819b2b6b30512

![](/images/Screenshot%202024-18-02%20100217.png)

After this, the malware will delete the backup files.

![](/images/Pasted%20image%2020240219234224.png)
> Function call to delete the backup files


### Get Random Byte 
Using the WinCrypt API, the malware will generate a random byte.
![](/images/Screenshot%202024-18-02%20174643.png)

![](/images/Screenshot%202024-19-02%20183241.png)
> Return value of the function

![](/images/Screenshot%202024-19-02%20183234.png)
> Random byte generated by the malware




### Encrypt Random Byte and get Decrypt String
The malware then calls a function that returns a base64 string with the random byte as its input. 
This is done by first encrypting the random byte.

![](/images/Screenshot%202024-18-02%20175135.png)

The malware gets the Crypt Context 
![](/images/Screenshot%202024-17-02%20095428.png)

![](/images/Pasted%20image%2020240219195622.png)

![](/images/Screenshot%202024-17-02%20095539.png)
>Source: wincrypt.h

The last two arguments specify the Cryptographic Provider type and the flags respectively. 
Hence, the ransomware uses PROV_RSA_AES as its Cryptographic Provider to encrypt the files. 
The flags set are either CRYPT_VERIFYCONTEXT or CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET.
The ransomware then imports a RSA key into the context and encrypts the random byte.
It generates this key based on the base64 string.

![](/images/Screenshot%202024-18-02%20175356.png)

![](/images/Screenshot%202024-16-02%20191311 1.png)
> **Return value of the get_key function**

This is the key that gets imported into the Cryptographic context. Since this key is derived from the original base64 string, this key will always be the same. 
The random byte is now encrypted and another base64 string is derived from it.

![](/images/Pasted%20image%2020240219202616.png)

This is also the same base64 string that is written to the HELP_PC.EZDZ-REMOVE.txt file. 




### Create a thread to encrypt each drive
The ransomware will get all the drives using the GetLogicalDrives. For each drive, the ransomware creates a separate thread to encrypt the contents of said drive. The file path is specified using the extended-length path syntax to bypass all normalization.

![](/images/Screenshot%202024-18-02%20180307.png)
![](/images/Screenshot%202024-18-02%20180435.png)
> Call to create thread

The encryption happens by first creating the HELP_PC.EZDZ-REMOVE.txt file in each directory that is about to be encrypted. 

![](/images/Screenshot%202024-18-02%20180539.png)

The ransomware will not encrypt a file if it is of type **FILE_ATTRIBUTE_DIRECTORY**.
The ransomware will encrypt all of the following file types:
* ***FILE_ATTRIBUTE_READONLY**(0x00000001)
* ***FILE_ATTRIBUTE_HIDDEN**(0x00000002)
* ***FILE_ATTRIBUTE_SYSTEM**(0x00000004)
* ***FILE_ATTRIBUTE_ARCHIVE**(0x00000020)
* ***FILE_ATTRIBUTE_NORMAL**(0x00000080)
Since 0x17 = 10100111

![](/images/Screenshot%202024-16-02%20181351.png)

The ransomware will not encrypt any file that has the string ".EZDZ" in its file name, since it is already encrypted. It will also not encrypt the 'help' file.
Finally, the malware will skip over all the files that are in a directory that contains the following substring.

![](/images/Pasted%20image%2020240219205031.png)

![](/images/Screenshot%202024-16-02%20182121.png)

This explains why files within certain directories did not get encrypted. 

![](/images/Screenshot%202024-18-02%20182022.png)

Each file is encrypted by opening the said file using CreateFileW, reading 8 bytes from the file, encrypting the bytes read, and then writing those encrypted bytes back to the original file.
This is only repeated for the first 0x20000 bytes. 

![](/images/Screenshot%202024-17-02%20103954.png)
> Difference between an encrypted file and the original file.

With this, we can confirm that only the first 0x20000 bytes are encrypted.

After this, the file name is changed by appending a .EZDZ extension to it. 

The actual encryption of the bytes read from each file happens by xoring them with a value that is derived based on the random byte that was generated at the beginning. 

![](/images/Screenshot%202024-18-02%20182418.png)




### Encrypt Network Resources 
The ransomware will then enumerate all the network resources and encrypt them in a similar manner.

![](/images/Screenshot%202024-17-02%20102946.png)




## Defanged Version
It is possible to create a benign version of this malware by patching the call to encrypt_file with NOP instructions. This can better enable dynamic analysis.
![](/images/Screenshot%202024-16-02%20181145.png)




## Decryption 
Since the random byte is only generated once each time the ransomware is executed, the first 0x20000 bytes of all the files are encrypted by xoring them with the same values. If we can get the original version of one of the encrypted files either by downloading it from the internet or from somewhere else, we can xor the first 0x20000 bytes of the encrypted file with the original file. This should give us the xor key. We can use this xor key to decrypt all the other files. 



## Indicators 
Since the malware does not exhibit any network functionality, it does not have any network-based indicators.
The IID values used to perform the UAC bypass and the original base64 string present in the malware are good host-based indicators.
The string "HELP_PC.EZDZ-REMOVE.txt" and the command "delete shadows /all /quiet" would be helpful in identifying this malware.
