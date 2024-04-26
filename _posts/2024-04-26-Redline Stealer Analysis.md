---
layout: post
title:  "Redline Stealer Analysis"
categories: [Malware-Analysis]
tags: [malware-analysis, windows-security, ]
---



# Redline Stealer Analysis

## Executive Summary 
The malware is a dotnet executable, which acts as an info stealer. It is obfuscated using ConfuserEx and string replacement.

The malware uses the Windows Communication Foundation(WCF) framework via TCP transport for C2 communications. The C2 configuration is encoded using base64 and XOR encoding. The configuration also contains an Authorization token, which is used to authenticate to the C2. The malware tries to connect to 194.26.135.119 and port 12432.

Information is exchanged between the malware and the C2 through Data and Service contracts. The malware gets its configuration from the C2 server using Data Contracts. This configuration object will be used by the malware to decide which files to scan. The configuration also contains other parameters such as file paths and a list of environment variables to steal. 

The extracted data is sent to the C2 using Data Contracts. The malware relies on Service Contracts to get further C2 functionality that enables it to send the data back to the server.

The malware uses native DLLs to get screenshots and to access cryptographic services. 

The malware will create a directory named \\ElevatedDiagnostics\\Reports in the users Local AppData directory to mark the user as infected.

The malware will exfiltrate the following information:
* System Information
* Hardware Information
* Installed Programs
* Running Processes
* Environment Variables
* FTP Credentials
* Steam credentials and VDF Files
* NordVPN Credentials 
* OpenVPN Credentials
* ProtonVPN Credentials
* Discord Tokens
* Telegram data
* Crypto Wallet data and credentials
* Browser credentials, cookies, credit card information, and auto-fill data.

<div style="page-break-after: always;"></div>

## Table of Contents

* Basic Static Analysis 
	* PE Analysis 
	* Imports
	* Strings
* Dynamic Analysis
* Static Analysis
	* C2 config decoding
	* WCF communication 
	* DataContract Renaming
	* Information Stealing (Stage 1)
	* Information Stealing (Stage 2)
		* System Details
		* Browser Name and Version
		* Programs
		* System Security
		* Processes
		* Language
		* Screenshot
		* Telegram
		* Discord
		* Steam
		* FTP (FileZilla)
		* VPNs
		* System Files
		* Browsers
		* Crypto Wallets
* Indicators of Compromise
	* Host Based
	* Network Based
	* Yara Rules
* Notes
	* Object Mapping
	* C2
<div style="page-break-after: always;"></div>


## Basic Static Analysis 

### PE Analysis 
![](/images/Pasted%20image%2020240410165107.png)
> Basic PE information 

MD5
36f088b87f6b24a47c2ac9ef6112bf25 
SHA-1
08ad229d1bb7b76516652d1fb00e309598754d49 
SHA-256
47f3fff50f1060bbe4e32a441488806a6bc7d4103fe1dfad6355dae73166b0df

According to the compiler stamp, the malware was compiled on **March 1st, 2071 at 07:03:48**.

The malware is a **Windows GUI program**.

Since the entropy is much lower than 7, the malware is likely not encrypted or packed. There is also no packing signature that indicates that the malware is packed. Furthermore, the virtual size is also not much bigger than the raw size, which is a good indication that the malware is **not encrypted or packed**. 

![](/images/Pasted%20image%2020240417114308.png)
> PE sections
<div style="page-break-after: always;"></div>

The **.text** file contains the program instructions.
The **.rsrc** contains file resources such as icons.
The **.reloc** section contains relocation information, which is used by the loader to adjust addresses.

![](/images/Pasted%20image%2020240417115255.png)
> Imports

The only import is the \_CorExeMain function. This, along with the signature,  indicates that this is a dotnet executable.

In the strings section, we see a string named "ConfusedByAttribute"
![](/images/Pasted%20image%2020240417115651.png)
> Strings

This indicates that the malware was obfuscated using ConfuserEx. We can de-obfuscate the malware using a tool called ConfuserEx2_String_Decryptor. 

### Imports
![](/images/Pasted%20image%2020240417120109.png)
> Imports after de-obfuscation

We can see a lot more imports now. 

**There are several suspicious classes and methods such as:** 
* CreateService
* SecureString (Used to view confidential text)
* DirectorySecurity (Used to access control and audit security for a directory)
* UnverifiableCodeAttribute
* Registry
* RegistryKey
* FromBase64String (Used to extracted encoded data)
* ToBase64String
* GetTempFileName
* WriteFile
* LoadLibrary (Used to dynamically load DLLs)
* GetProcAddress (Used to dynamically find function addresses)

**Suspicious network-related classes and methods:**
* MailMessage
* WebResponse
* WebRequest
* IPAddress
* NetworkInterface
* SmtpClient
* WebException
* IPInterfaceProperties
* UnicastIPAddressInformationCollection
* UnicastIPAddressInformation
* IPAddressInformation
* AddressFamily
* OperationalStatus
* NetworkInterfaceComponent
* GatewayIPAddressInformationCollection
* GatewayIPAddressInformation
* Send

Suspicious cryptography-related classes and methods:
* DataProtectionScope
* CspParameters
* RSACryptoServiceProvider
* CryptographicException
* ProtectedData
* MD5CryptoServiceProvider

**Suspicious namespaces:**
![](/images/Pasted%20image%2020240417121907.png)
> Namespaces

* System.Security (Used to access system security parameters)
* System.Security.AccessControl (Enumerate and modify ACLs)
* System.Net.Mail
* System.Net (C2 Communication)
* System.Security.Cryptography
* System.Net.NetworkInformation 
* System.Net.Sockets (C2 Communication)
### Strings
![](/images/Pasted%20image%2020240417122534.png)
> Strings

There are several suspicious strings such as:
* ConfusedByAttribute (ConfuserEx obfuscation indicator)
* 41.11.2.0 (Possible IP)
* https://api.ip.sb/ip (API Endpoint to get current machines IP)
* SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall (Registry entry to enumerate installed programs)

![](/images/Pasted%20image%2020240417123036.png)
> Base64 encoded strings
<div style="page-break-after: always;"></div>

## Dynamic Analysis 

The malware does set a few registry entries, but the malware does not modify or create any suspicious registry values.

![](/images/Pasted%20image%2020240417221015.png)
> Registry Keys being set

The malware will create a directory named  **\\ElevatedDiagnostics\\Reports** in the user's AppData\\Local Directory to mark the victim as infected. If the directory already exists and is older than 14 days, it will delete it and create a new one.

The malware does not start any services or processes. However, the malware uses the WMI service to gather information.

 ![](/images/Pasted%20image%2020240410193135.png)
> Network activity 

![](/images/Pasted%20image%2020240414230502.png)
> Packet body 

The malware attempts to connect to **194.26.135.119 at port 12432.** The 'net.tcp' URI indicates that the malware uses WCF for C2 communications. 

![](/images/Pasted%20image%2020240417220535.png)
> Process Hacker

![](/images/Pasted%20image%2020240417111830.png)
> IP information

If the malware fails to get the IP information of the victim's device, it will query the IP.SB API at https://ip.sb/api/ip to get the victim IP. 
<div style="page-break-after: always;"></div>

## Static Analysis

After de-obfuscation, the malware can be further analyzed in DnSpy. 

The malware's entry point is MainFrm
![](/images/Pasted%20image%2020240417183512.png)
> Entry Point

![](/images/Pasted%20image%2020240410175633.png)
> MainFrm class

### C2 Config Decoding

The malware begins by decoding C2 configuration.

![](/images/Pasted%20image%2020240417141739.png)
> C2 Arguments

![](/images/Pasted%20image%2020240417141808.png)
> Decoding

Decoding is accomplished by first base64 decoding the string, then XORing it with the key string, and finally base64 decoding it again.

We can see the decoded values by using DnSpy's built-in debugger.

![](/images/Pasted%20image%2020240413102635.png)
> Decoded IP

The configuration also contains an ID value, which is used by the C2 to identify the malware.

It will iterate through each address present in the config until the malware finds a live C2. 

![](/images/Pasted%20image%2020240410175940.png)
> Authorization Token

### WCF Communications

The malware will try to connect to the C2 server using NET.TCP protocol. It will also include and Authorization token header, which is used to authenticate to the C2. 

The malware imports classes such as DataContractAttribute and OperationContractAttribute for Data and Service contracts. Based on this and the fact that the malware is using net.tcp, the malware is using WCF.

The malware exchanges data with the C2 server using data contracts.
The malware also makes use of service contracts for C2 communications.
![](/images/Pasted%20image%2020240416193319.png)
> Service Contract

After establishing a connection with the C2 server, the malware gets a 'Settings' object from the server, which is used to determine the behavior of the malware. 

![](/images/Pasted%20image%2020240417144417.png)
> Settings 

![](/images/Pasted%20image%2020240417144454.png)
> Settings class

The names of the data members for every DataContract in this malware are anonymized for the sake of OPSEC. However, we can surmise what each of the values represents as we analyze the malware.

### DataContract Remaning
#### Settings Class (MSValue18)

| Original Name | After Reversing | Type               |
| ------------- | --------------- | ------------------ |
| MSValue1      | Browsers        | bool               |
| MSValue2      | Files           | bool               |
| MSValue3      | FTP             | bool               |
| MSValue4      | Wallets         | bool               |
| MSValue5      | Screen          | bool               |
| MSValue6      | Telegram        | bool               |
| MSValue7      | VPNs            | bool               |
| MSValue8      | Steam           | bool               |
| MSValue9      | Discord         | bool               |
| MSValue10     | LocalFiles      | List\<string\>     |
| MSValue11     | ChromePaths     | List\<string\>     |
| MSValue12     | FirefoxPaths    | List\<string\>     |
| MSValue13     | WalletConfig    | List\<WalletConf\> |
| MSValue14     | WalletPaths     | string             |
| MSValue15     | EnvironmentVar  | List\<string\>     |
The malware will use these config values to collect data and store it in a 'Result' object.
#### Result Class (MSValue7)

| Original Name | After Reversing | Type        |
| ------------- | --------------- | ----------- |
| MSValue1      | Hardware        | string      |
| MSValue2      | MalwareID       | string      |
| MSValue3      | MachineName     | string      |
| MSValue4      | OSVersion       | string      |
| MSValue5      | Language        | string      |
| MSValue6      | Resolution      | string      |
| MSValue7      | ScanDetails     | ScanDetails |
| MSValue8      | Not Used        | string      |
| MSValue9      | Not Used        | string      |
| MSValue10     | TimeZone        | string      |
| MSValue11     | IP              | string      |
| MSValue12     | Monitor         | byte \[\]   |
| MSValue13     | ZIP             | string      |
| MSValue14     | FileLocation    | string      |
| MSValue15     | SeenBefore      | bool        |
#### ScanDetails Class (MSValue1)

| Original Name | After Reversing | Type                         |
| ------------- | --------------- | ---------------------------- |
| MSValue1      | SystemSecurity  | List\<string\>               |
| MSValue2      | Languages       | List\<string\>               |
| MSValue3      | Programs        | List\<string\>               |
| MSValue4      | Processes       | List\<string\>               |
| MSValue5      | SystemDetails   | List\<System\>               |
| MSValue6      | Browsers        | List\<Browser\>              |
| MSValue7      | FTP             | List\<Account\>              |
| MSValue8      | BrowserVersion  | List\<BrowserVersion\>       |
| MSValue9      | SystemFiles     | List\<ScannedFile\>          |
| MSValue10     | Steam           | List\<ScannedFile\>          |
| MSValue11     | Wallets         | List\<ScannedFile\>          |
| MSValue12     | NordVPN         | List\<ScannedFile\>          |
| MSValue13     | OpenVPN         | List\<ScannedFile\>          |
| MSValue14     | ProtonVPN       | List\<ScannedFile\>          |
| MSValue15     | Telegram        | List\<ScannedFile\>          |
| MSValue16     | Discord         | List\<ScannedFile\>          |
| MSValue18     | EnvironmentVars | Dictionary\<string, string\> |

![](/images/Pasted%20image%2020240414202708.png)
> Info Stealing Handler Stages

![](/images/Pasted%20image%2020240416155350.png)
> Scanning for IPv4 address 

The malware will try to enumerate the non-local IP addresses present on all the interfaces (except the loopback interface). If it fails to get any addresses, the malware will make a request to an API service at https://api.ip.sb/ip to get the victim's IP.

The malware uses Windows-1251 encoding, which is used for languages that use Cyrillic script such as Russian, Ukrainian, Belarusian, etc.
![](/images/Pasted%20image%2020240415001751.png)
> Windows-1251

The malware will mark the victim as infected by creating a directory in the user's AppData\\Local directory. If this directory does not exist, it will create one and set the 'SeenBefore' value to false. If the directory is older than 14 days, it will delete the directory and set the 'SeenBefore' value to true.
![](/images/Pasted%20image%2020240416155858.png)
> SeenBefore

![](/images/Pasted%20image%2020240416161557.png)
> PreCheck

The malware will also make sure to reset all the values in the 'Results' object before starting.  

After this, the malware collects victim information in two stages. 

<div style="page-break-after: always;"></div>


#### Information Stealing (Stage 1)
![](/images/Pasted%20image%2020240416161250.png)
> First stage of information stealing

The malware gets the system resolution by calling GetSystemMetrics from user32.dll. 
The malware will get the Windows version by querying registry keys.
It will also get the serial number of the drive by using WQL(WMI Query Language). 
#### Information Stealing (Stage 2)
![](/images/Pasted%20image%2020240416162017.png)
> Second stage of information stealing

The malware uses WQL again to get more system information.

![](/images/Pasted%20image%2020240416162111.png)
> Browser-related registry keys

The malware gets browser names and browser versions by querying the registry keys.

The malware will enumerate installed programs
![](/images/Pasted%20image%2020240416162144.png)
> Registry keys for installed programs

The malware also gets a list of all the running processes.
![](/images/Pasted%20image%2020240416162724.png)
> WQL query to find running processes

The malware also uses string replacement to some of it's strings. 

The malware will make use of WMI's AntiSpywareProduct and 
AntiVirusProduct class to get information about AV/EDR. 

The malware will get a list of languages used by the victim's machine.
![](/images/Pasted%20image%2020240416162805.png)
> Language

The malware can also get a screenshot of the victim device using the CopyFromScreen method.
![](/images/Pasted%20image%2020240416171731.png)
> Screenshot

The malware can also capture the values of all the environment variables that were specified in its Settings.
![](/images/Pasted%20image%2020240416171815.png)
> Environment variables

#### File Scanning

The malware uses a File Scanner class that takes in a File Scanning Rule and outputs a list of Scanned Files.
![](/images/Pasted%20image%2020240416163851.png)
> File Scanner

It uses the Get.Directories and Get.Files method to search for files and traverse directories.  

![](/images/Pasted%20image%2020240416164420.png)
> ScannedFile Class

The constructer for the ScannedFile class will copy the file once the class is initialized. 
#### Telegram
![](/images/Pasted%20image%2020240416172556.png)
> Telegram process

The malware will look Telegram.exe process and get files from the \\tdata directory where Telegram stores session data.

![](/images/Pasted%20image%2020240416172113.png)
> Telegram Data
#### Discord
![](/images/Pasted%20image%2020240416172822.png)
> Discord

The malware will look for .log and .db files and try to get Discord tokens which are used to encrypt Discord credentials. It will use a regex pattern to search for these tokens.

![](/images/Pasted%20image%2020240416173008.png)
> Regex Pattern Search
```regex
[A-Za-z\\d]{24}\\.[\\w-]{6}\\.[\w-]{27}
```
#### Steam
![](/images/Pasted%20image%2020240416173546.png)
> Steam

The malware will look for VDF(Valve Data format) Files, and  SSFN (Steam Sentry) Files. 
#### FTP (FileZilla)
![](/images/Pasted%20image%2020240416175539.png)
> FileZilla Files

![](/images/Pasted%20image%2020240416175522.png)
> FTP Credentials

The malware searches for FileZilla credentials and creates an Account object that contains URL, username and password.
#### VPNs
The malware will exfiltrate VPN related files for NordVPN, OpenVPN and ProtonVPN.
##### NordVPN
![](/images/Pasted%20image%2020240416180044.png)
> NordVPN Files 

![](/images/Pasted%20image%2020240416190434.png)
> Crypto Functions

The malware will extract NordVPN credentials from the user.config file. It will also use BCrypt* functions from bcrypt.dll to decrypt the credentials.

![](/images/Pasted%20image%2020240417200314.png)
> LoadLibrary Usage

![](/images/Pasted%20image%2020240417200213.png)
> GetProcAddress Usage
##### OpenVPN
![](/images/Pasted%20image%2020240416180121.png)
> OpenVPN files

The malware will steal OpenVPN files from the %AppData% directory. 
##### Proton VPN
![](/images/Pasted%20image%2020240416180444.png)
> ProtonVPN files

#### System Files

To malware can also exfiltrate local system files.

#### Browsers
The Settings class contains a list of paths for Chromium-based browsers and Firefox. The malware uses this list to search for sensitive files.
##### Chromium Browsers

![](/images/Pasted%20image%2020240416185309.png)
> Browser Class

For Chromium-based browsers, the malware will collect the following data:

**Browser Name**

**Browser Profile Name**

**Account Data**
![](/images/Pasted%20image%2020240416184835.png)
> Account Class

**Credit Card Information**
![](/images/Pasted%20image%2020240416185141.png)
> Credit Card Class

Cookies
![](/images/Pasted%20image%2020240416185330.png)
> LoginData Class

Auto Fill Data
![](/images/Pasted%20image%2020240416185346.png)
> AutoFills

The malware also uses the bcrypt library here to decrypt data.
##### Firefox Browser
![](/images/Pasted%20image%2020240416190021.png)
> Cookies

For Firefox, the malware will look for sqlite databases that contain confidential browser information.

#### Wallets
Based on the Settings received from the C2 server, the malware will also search for and exfiltrate crypto wallet information. Mainly from the %AppData% folder.
![](/images/Pasted%20image%2020240416191510.png)
> Wallet Information Gathering
<div style="page-break-after: always;"></div>


## Indicators of Compromise

### Host-Based 
Sample3.exe 
Hash: 08ad229d1bb7b76516652d1fb00e309598754d49

\\ElevatedDiagnostics\\Reports in the user's AppData\\Local 
### Network-Based 

194.26.135.119 and port 12432
https://api.ip.sb/ip 
<div style="page-break-after: always;"></div>


### Yara Rules

### Sample3
```yara
import "pe"
rule redline{
	meta:
		author = "Sid"
		description = "YARA rule to detect Redline Malware" 
	strings:
		$a1 = "ConfusedByAttribute"	
		$a2 = "LoadLibrary"
		$a3 = "GetProcAddress"
		$a4 = "_CorExeMain"
		$opt1 = "CreateService"
		$opt2 = "GetTempFileName"
		$opt3 = "System.Security.Cryptography"
		$opt4 = "System.Security.AccessControl"
		$opt5 = "FromBase64String"
		$opt6 = "ToBase64String"
		$opt7 = /BCRYPT_[a-zA-Z0-9_]+/
		$opt8 = "ManagementObjectSearcher"
		$opt9 = "GetGraphicsCard"
		$opt10 = "GetAllNetworkInterfaces"
		$wcf1 = /System.ServiceModel.[a-zA-Z]/
		$wcf2 = "DataContractAttribute"
		$wcf3 = "ServiceContractAttribute"
	condition:
		pe.is_pe and (all of ($a*)) and (7 of ($opt*)) and (2 of ($wcf*)) 
}

```

> Source: https://cyber-anubis.github.io/malware%20analysis/redline/

<div style="page-break-after: always;"></div>


## Notes
### Object Mapping

| Code    | Description             |
| ------- | ----------------------- |
| MSObj1  | ScanDetails             |
| MSObj3  | System                  |
| MSObj5  | ScannedFile             |
| MSObj8  | AutoFills               |
| MSObj9  | Browser                 |
| MSObj7  | Results                 |
| MSObj10 | Cookies/LoginData       |
| MSObj11 | Credit Card             |
| MSObj12 | Accounts                |
| MSObj13 | Main Info Stealer       |
| MSObj14 | Hardware Info           |
| MSObj16 | Scanner Args            |
| MSObj17 | WalletConfig            |
| MSObj18 | Settings                |
| MSObj19 | FTPScanner Rule         |
| MSObj20 | Firefox Scanner Rule    |
| MSObj21 | Nord VPN Scanner Rule   |
| MSObj23 | Wallet Scanner Rule     |
| MSObj26 | Discord Scanner Rule    |
| MSObj27 | Steam Scanner Rule      |
| MSObj28 | Open VPN Scanner Rule   |
| MSObj29 | Proton VPN Scanner Rule |
| MSObj31 | File Scanner            |
| MSObj32 | Local File Scanner Rule |
| XPOM    | Chrome Scanner Rule     |


To make a C2 server for this malware, we need to install the WCF library from VS Installer.

![](/images/Pasted%20image%2020240415145246.png)
> WCF library 