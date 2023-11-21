---
layout: post
title: MetaStealer - Redline's Doppelgänger
description: MetaStealer malware analysis
date: 2023-11-20 7:01:35 +0300
image: /images/MetaStealer/meta_header.png
---

# Case Study

MetaStealer made its debut on Russian hacking forums on March 7, 2022. The stealer is said to incorporate the functionality, code, and panel of Redline Stealer. The developer claims to have improved the stub of the payload. It is priced at $150 per month, mirroring the price of Redline Stealer.

![meta-ads.jpg](/images/MetaStealer/meta-ads.JPG)

**Note:** Some samples of MetaStealer have been found in sandbox platforms like Triage, Joe Sandbox, Any.run and classified as Redline or ["another" MetaStealer"](https://malpedia.caad.fkie.fraunhofer.de/details/win.metastealer) that appears to be written in C++. You can find an example [here](https://tria.ge/231027-nzmhssfg49/behavioral2). Additionally, SentinelOne has [reported](https://www.sentinelone.com/blog/macos-metastealer-new-family-of-obfuscated-go-infostealers-spread-in-targeted-attacks/) a separate MetaStealer targeting MacOS devices that is written in Golang. It's important to note that these are not the same malware variants. To clarify, the MetaStealer I am analyzing is written in C#.

The developer of MetaStealer actively advertises **crypter[.]guru** crypting services for their stealer users, as can be seen in the screenshot below.

![crypt_guru.jpg](/images/MetaStealer/crypt_guru.JPG)

I will provide a brief overview of some of the stealer's functionalities, but we won't delve into extensive detail as it shares many similarities with Redline Stealer. For a more comprehensive analysis, you can refer to my Redline writeup [here](https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-redline-stealer)

# Technical Analysis

The generated MetaStealer build is automatically obfuscated with Confuser Core 1.6.0. Notably, the binary description contains the text "METRO 2022 Dev," suggesting that the malware developer may be a fan of the Metro franchise :)

![file_sig.jpg](/images/MetaStealer/file_sig.JPG)

I proceeded with cleaning up the sample a bit to make it more readable and reversible. We go to the entry point of the binary and notice some interesting code within class "MainFrm" and "ReadLine" methods. Within "ReadLine" method, we see a **while** loop that continues as long as a boolean variable **flag** is **false**.
Inside this loop, it calls **StringDecrypt.Read(Arguments.IP, Arguments.Key)**, which retrieves two arguments **IP** and **key**. The retrieved data is split into an array of strings using the  "|" character as a delimiter.

![readline_method.jpg](/images/MetaStealer/readline_method.JPG)

The **Read** method takes two string parameters, **b64** and **stringKey**. The method first checks if the **b64** parameter is null, empty, or consists only of white-space characters (**if (string.IsNullOrWhiteSpace(b64))**. If **b64** is not null or white-space, the method performs a series of operations:

- It first decodes **b64** from Base64 format. The result of this decoding is a string (**StringDecrypt.FromBase64(b64)**).
- It then applies an XOR operation to the decoded string using **stringKey** as the key.
- The result of the XOR operation is then decoded again from Base64 format. 

![read_method.jpg](/images/MetaStealer/read_method.JPG)

Looking at the Arguments table, we can see some interesting base64-encoded strings:

![arguments_table.jpg](/images/MetaStealer/arguments_table.JPG)

This is **StringDecrypt** class, where XOR decryption takes place:

![xor_fn.jpg](/images/MetaStealer/xor_fn.JPG)

For each character in **input**, it performs an XOR operation with the corresponding character in **stringKey** as shown in the Arguments table. The index for **stringKey** is determined by **i % stringKey.Length**, ensuring that if **stringKey** is shorter than **input**, it will repeat from the very beginning. The exact similar string encryption is used for Redline as well.

Upon decrypting the string in CyberChef, we get the C2 IP and the port number.

![cyberchef.jpg](/images/MetaStealer/cyberchef.JPG)

Next, we will look at **method_03**. The code is responsible for setting up network communication. 
- It attempts to establish a network channel to a remote endpoint specified by the **address** argument. This involves creating a [**ChannelFactory**](https://learn.microsoft.com/en-us/dotnet/api/system.servicemodel.channelfactory?view=dotnet-plat-ext-7.0) with a specific binding and endpoint address.
- It then sets up credentials and bypasses certificate validation.
- Next, it adds an "Authorization" message header with a hardcoded value (token/key) that is likely for authentication purposes (for example, **{xmlns="ns1">ead3f92ffddf3eebb6b6d82958e811a0}**)
- It then returns **true** if the connection setup is successful, **false** if any exception occurs

![method_3_comms.jpg](/images/MetaStealer/method_3_comms.JPG)

**method_0** contains **MSValue1**, which is a call to a method on a WCF (Windows Communication Foundation) service channel and the **connector** object is a proxy facilitating the remote method invocation.

![MSValue1.jpg](/images/MetaStealer/MSValue1.JPG)

Next, we will reach **method_2**:

![method2.jpg](/images/MetaStealer/method2.JPG)

It calls **this.connector.OnGetSettings()**, which seems to be a method call to obtain some data from C2. The result is assigned to the **msobject** variable.
**OnGetSettings** method is responsible for retrieving settings data and packaging it into an instance of the **MSObject18** class. 

![ongetsettings.png](/images/MetaStealer/ongetsettings.png)

Each MSValue (MSValue10, MSValue11, MSValue12 etc.) stores the configuration retrieved from C2:
- **MSValue10** - stores the grabber configuration:

{% highlight xml %}

@"%userprofile%\\Desktop|*.txt,*.doc*,*key*,*wallet*,*seed*|0"
@"%userprofile%\\Documents|*.txt,*.doc*,*key*,*wallet*,*seed*|0"

{% endhighlight%}

- **MSValue11** - stores the paths to the "User Data" folder for various browsers and applications such as Steam and Battle.net to steal the sensitive information from:

{% highlight xml %}

@"%USERPROFILE%\\AppData\\Local\\Battle.net"
@"%USERPROFILE%\\AppData\\Local\\Chromium\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Google(x86)\\Chrome\\User Data"
@"%USERPROFILE%\\AppData\\Roaming\\Opera Software\\"
@"%USERPROFILE%\\AppData\\Local\\MapleStudio\\ChromePlus\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Iridium\\User Data"
@"%USERPROFILE%\\AppData\\Local\\7Star\\7Star\\User Data"
@"%USERPROFILE%\\AppData\\Local\\CentBrowser\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Chedot\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Vivaldi\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Kometa\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Elements Browser\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Epic Privacy Browser\\User Data"
@"%USERPROFILE%\\AppData\\Local\\uCozMedia\\Uran\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer"
@"%USERPROFILE%\\AppData\\Local\\CatalinaGroup\\Citrio\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Coowon\\Coowon\\User Data"
@"%USERPROFILE%\\AppData\\Local\\liebao\\User Data"
@"%USERPROFILE%\\AppData\\Local\\QIP Surf\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Orbitum\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Comodo\\Dragon\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Amigo\\User\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Torch\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Yandex\\YandexBrowser\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Comodo\\User Data"
@"%USERPROFILE%\\AppData\\Local\\360Browser\\Browser\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Maxthon3\\User Data"
@"%USERPROFILE%\\AppData\\Local\\K-Melon\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Sputnik\\Sputnik\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Nichrome\\User Data"
@"%USERPROFILE%\\AppData\\Local\\CocCoc\\Browser\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Uran\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Chromodo\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Mail.Ru\\Atom\\User Data"
@"%USERPROFILE%\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data"
@"%USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data"
@"%USERPROFILE%\\AppData\\Local\\NVIDIA Corporation\\NVIDIA GeForce Experience"
@"%USERPROFILE%\\AppData\\Local\\Steam"
@"%USERPROFILE%\\AppData\\Local\\CryptoTab Browser\\User Data"
{% endhighlight%}

- **MSValue12** contains additional browser paths and Thunderbird:

{% highlight xml %}

@"%USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox"
@"%USERPROFILE%\\AppData\\Roaming\\Waterfox"
@"%USERPROFILE%\\AppData\\Roaming\\K-Meleon"
@"%USERPROFILE%\\AppData\\Roaming\\Thunderbird"
@"%USERPROFILE%\\AppData\\Roaming\\Comodo\\IceDragon"
@"%USERPROFILE%\\AppData\\Roaming\\8pecxstudios\\Cyberfox"
@"%USERPROFILE%\\AppData\\Roaming\\NETGATE Technologies\\BlackHaw"
@"%USERPROFILE%\\AppData\\Roaming\\Moonchild Productions\\Pale Moon"

{% endhighlight%}

- **MSValue13** - stores cryptowallet information under %AppData%
- **MSValue14** - stores cryptowallet extensions:

{% highlight xml %}

ffnbelfdoeiohenkjibnmadjiehjhajb|YoroiWallet\r\nibnejdfjmmkpcnlpebklmnkoeoihofec|Tronlink\r\njbdaocneiiinmjbjlgalhcelgbejmnid|NiftyWallet\r\nnkbihfbeogaeaoehlefnkodbefgpgknn|Metamask\r\nafbcbjpbpfadlkmhmclhkeeodmamcflc|MathWallet\r\nhnfanknocfeofbddgcijnmhnfnkdnaad|Coinbase\r\nfhbohimaelbohpjbbldcngcnapndodjp|BinanceChain\r\nodbfpeeihdkbihmopkbjmoonfanlbfcl|BraveWallet\r\nhpglfhgfnhbgpjdenjgmdgoeiappafln|GuardaWallet\r\nblnieiiffboillknjnepogjhkgnoapac|EqualWallet\r\ncjelfplplebdjjenllpjcblmjkfcffne|JaxxxLiberty\r\nfihkakfobkmkjojpchpfgcmhfjnmnfpi|BitAppWallet\r\nkncchdigobghenbbaddojjnnaogfppfj|iWallet\r\namkmjjmmflddogmhpjloimipbofnfjih|Wombat\r\nfhilaheimglignddkjgofkcbgekhenbh|AtomicWallet\r\nnlbmnnijcnlegkjjpcfjclmcfggfefdm|MewCx\r\nnanjmdknhkinifnkgdcggcfnhdaammmj|GuildWallet\r\nnkddgncdjgjfcddamfgcmfnlhccnimig|SaturnWallet\r\nfnjhmkhhmkbjkkabndcnnogagogbneec|RoninWallet\r\naiifbnbfobpmeekipheeijimdpnlpgpp|TerraStation\r\nfnnegphlobjdpkhecapkijjdkgcjhkib|HarmonyWallet\r\naeachknmefphepccionboohckonoeemg|Coin98Wallet\r\ncgeeodpfagjceefieflmdfphplkenlfk|TonCrystal\r\npdadjkfkgcafgbceimcpbkalnfnepbnk|KardiaChain\r\nbfnaelmomeimhlpmgjnjophhpkkoljpa|Phantom\r\nfhilaheimglignddkjgofkcbgekhenbh|Oxygen\r\nmgffkfbidihjpoaomajlbgchddlicgpn|PaliWallet\r\naodkkagnadcbobfpggfnjeongemjbjca|BoltX\r\nkpfopkelmapcoipemfendmdcghnegimn|LiqualityWallet\r\nhmeobnfnfcmdkdcmlblgagmfpfboieaf|XdefiWallet\r\nlpfcbjknijpeeillifnkikgncikgfhdo|NamiWallet\r\ndngmlblcodfobpdpecaadgfbcggfjfnm|MaiarDeFiWallet\r\nejbalbakoplchlghecdalmeeeajnimhm|MetaMask Edge\r\nmlbafbjadjidklbhgopoamemfibcpdfi|GoblinWallet

{% endhighlight%}

- **MSValue15** - stores the environmental variables for tokens and keys:

{% highlight xml %}

"AWS_ACCESS_KEY_ID"
"AWS_SECRET_ACCESS_KEY"
"AMAZON_AWS_ACCESS_KEY_ID"
"AMAZON_AWS_SECRET_ACCESS_KEY"
"ALGOLIA_API_KEY"
"AZURE_CLIENT_ID"
"AZURE_CLIENT_SECRET"
"AZURE_USERNAME"
"AZURE_PASSWORD"
"MSI_ENDPOINT"
"MSI_SECRET"
"binance_api"
"binance_secret"
"BITTREX_API_KEY"
"BITTREX_API_SECRET"
"CF_PASSWORD"
"CF_USERNAME"
"CODECLIMATE_REPO_TOKEN"
"COVERALLS_REPO_TOKEN"
"CIRCLE_TOKEN"
"DIGITALOCEAN_ACCESS_TOKEN"
"DOCKER_EMAIL"
"DOCKER_PASSWORD"
"DOCKER_USERNAME"
"DOCKERHUB_PASSWORD"
"FACEBOOK_APP_ID"
"FACEBOOK_APP_SECRET"
"FACEBOOK_ACCESS_TOKEN"
"FIREBASE_TOKEN"
"FOSSA_API_KEY"
"GH_TOKEN"
"GH_ENTERPRISE_TOKEN"
"CI_DEPLOY_PASSWORD"
"CI_DEPLOY_USER"
"GOOGLE_APPLICATION_CREDENTIALS"
"GOOGLE_API_KEY"
"CI_DEPLOY_USER"
"CI_DEPLOY_PASSWORD"
"GITLAB_USER_LOGIN"
"CI_JOB_JWT"
"CI_JOB_JWT_V2"
"CI_JOB_TOKEN"
"HEROKU_API_KEY"
"HEROKU_API_USER"
"MAILGUN_API_KEY"
"MCLI_PRIVATE_API_KEY"
"MCLI_PUBLIC_API_KEY"
"NGROK_TOKEN"
"NGROK_AUTH_TOKEN"
"NPM_AUTH_TOKEN"
"OKTA_CLIENT_ORGURL"
"OKTA_CLIENT_TOKEN"
"OKTA_OAUTH2_CLIENTSECRET"
"OKTA_OAUTH2_CLIENTID"
"OKTA_AUTHN_GROUPID"
"OS_USERNAME"
"OS_PASSWORD"
"PERCY_TOKEN"
"SAUCE_ACCESS_KEY"
"SAUCE_USERNAME"
"SENTRY_AUTH_TOKEN"
"SLACK_TOKEN"
"square_access_token"
"square_oauth_secret"
"STRIPE_API_KEY"
"STRIPE_DEVICE_NAME"
"SURGE_TOKEN"
"SURGE_LOGIN"
"TWILIO_ACCOUNT_SID"
"CONSUMER_KEY"
"CONSUMER_SECRET"
"TRAVIS_SUDO"
"TRAVIS_OS_NAME"
"TRAVIS_SECURE_ENV_VARS"
"VAULT_TOKEN"
"VAULT_CLIENT_KEY"
"TOKEN"
"VULTR_ACCESS"
"VULTR_SECRET"

{% endhighlight%}

Let's look at the Redline sample where it stores the configuration from the sample I analyzed at the end of 2022 and MetaStealer. We can see that MetaStealer is using MSObject* instead of Entity* objects as well as MSValue* instead of Id*. MetaStealer also uses a different type of collections. Redline Stealer uses *System.Collections.Generic.IEnumerable<Entity16> {Entity16[]}* , which represents a sequence of items of type *Entity16*, and the data shown is an array of *Entity16* objects. Metastealer uses *System.Collections.Generic.List<string>*, which represents a dynamic list of strings. 

![MetaRedline.drawio.png](/images/MetaStealer/MetaRedline.drawio.png)

Next, MetaStealer proceeds with decrypting the binary ID, which is the same XOR algorithm described earlier for retrieving the IP address.
Further down, I stumbled across the code that is responsible for extracting the data from the byte array and performing the string replacement. Thanks [@cod3nym](https://twitter.com/cod3nym) for pointing out that it's part of ConfuserEx default constant encryption runtime. 

![confuserex.jpg](/images/MetaStealer/confuserex.JPG)

Some of the retrieved strings are then getting replaced:

![str_replace 1.jpg](/images/MetaStealer/str_replace.JPG)

The stealer retrieves the memory with the WMI query **SELECT * FROM Win32_OperatingSystem**. Next, it retrieves the Windows version via the registry:

![winversion.jpg](/images/MetaStealer/winversion.JPG)

Interestingly enough, the stealer checks if the directory at the **AppData\\Local\\ElevatedDiagnostics** path exists. If the directory does not exist, it creates the directory. If the directory exists, it then checks if it was created more than 14 days ago (by comparing the directory's creation time to the current time minus 14 days). If the directory is older than 14 days, it deletes and recreates it. This stealer might be trying to clean up old diagnostic reports to hide any traces of execution. 

The code below is  responsible for screenshot capture.

- **GetVirtualDisplaySize**  method retrieves the size of the virtual display on a system, which encompasses all the screen area across multiple monitors
- **GetImageBase** method is designed to capture an image of the virtual display. First, it retrieves the virtual display size using the **GetVirtualDisplaySize** method. It then creates a new **Bitmap** object with the dimensions of the virtual display.
- **ConvertToBytes** method is used to convert an **Image** object to a byte array, presumably for storage or transmission. If the provided image is not null, it saves the image into a **MemoryStream** in PNG format. The contents of the memory stream are then converted to a byte array.

![get_Screenshot.jpg](/images/MetaStealer/get_Screenshot.JPG)

MetaStealer uses the WMI query **SELECT * FROM Win32_DiskDrive** to retrieve information (Serial number) of the physical disk drives.

The code below computes an MD5 hash based on the user's domain name, username, and serial number retrieved from the query above. The **GetHexString** method is used to convert bytes into a hexadecimal representation. It processes each byte in the byte array, converting every 4 bits into a hexadecimal character and adds hyphens after every 2 characters (equivalent to every 4 hexadecimal digits) in the generated hash) and then removes them (for example **4E6B8D28B175A2BE89124A80E77753C9**). The result is stored in **MSValue1** within **MSObject7**. This will be the HWID value.

The stealer proceeds with enumerating the infected system for FileZilla (C:\\Users\\username\\AppData\\Roaming\\FileZilla\\recentservers.xml). Next, it enumerates AV products using the following WMI queries:

- SELECT displayName FROM AntiVirusProduct
- SELECT displayName FROM AntiSpyWareProduct 
- SELECT displayName FROM FirewallProduct 

The stealer then proceeds with enumerating the directories for VPN apps such as NordVPN, OpenVPN Connect, ProtonVPN within **FileScannerRule** class. It retrieves a list of **FileInfo** objects by scanning a directory specified by **msobject.MSValue1** using the **EnumerateFiles** method. The **SearchOption** parameter determines whether the search is recursive (**SearchOption.AllDirectories**) or limited to the top directory only (**SearchOption.TopDirectoryOnly**).

The stealer retrieves information about running processes via the query **SELECT * FROM Win32_Process Where SessionId='"** as well as the command line for each process:

![running_proc.jpg](/images/MetaStealer/running_proc.JPG)

**Search** method is responsible for searching for files within certain directories (Windows, Program Files, Program Files (x86)). The BaseDirectory is where the search begins, for example, "C:\\Users\\username\\AppData\\Local\Battle.net". 

**GetBrowser** method gets the information on the installed browsers on the infected machine. 1. It attempts to access the Windows Registry to retrieve information about web browsers installed on the system. It opens a specific Registry key path under **HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Clients\StartMenuInternet** This key is used to store information about web browsers on 64-bit Windows systems. If the first attempt to open the key is unsuccessful, it falls back to opening a similar key path without the "WOW6432Node" part under **HKEY_LOCAL_MACHINE\SOFTWARE\Clients\StartMenuInternet** (32-bit Windows systems). After successfully opening the appropriate Registry key, it retrieves the names of its subkeys (which represent different web browsers) using the **GetSubKeyNames()** method. Within the loop of iterating through the list of browsers, it creates an instance of an object named **MSObject4**, which is used to store information about each web browser. The stealer  opens a subkey under the current browser's key path, which corresponds to the "shell\\open\\command" key, to retrieve the command line associated with launching the browser. This command line is stored in **msobject.MSValue3**. It then checks if **msobject.MSValue3** is not null and then retrieves the file version of the browser executable using **FileVersionInfo.GetVersionInfo(msobject.MSValue3).FileVersion**.

![getbrowsers.jpg](/images/MetaStealer/getbrowsers.JPG)

The processor information is retrieved via the query **SELECT * FROM Win32_Processor"* within *GetProcessors** method. 

The list of installed programs is retrieved within **ListofPrograms** method by accessing the registry key **SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall**. 

The basic information gathered such as the timezone, the build ID, stealer name, username, Windows version, screen size, MD5 hash (based on the user's domain name, username, and serial number), language settings are stored under **results** variable and the stealer configuration is stored under **settings** variable. 

Here is the snippet of the C2 communication with MetaStealer:

![traffic1.png](/images/MetaStealer/traffic1.png)

Redline for comparison:

![redline_traffic.png](/images/MetaStealer/redline_traffic.png)

So how do you differentiate between two stealers if they are very similar? That's right, the easiest way is probably based on traffic. The traffic for MetaStealer would slightly be different than for Redline Stealer. MetaStealer would have the indicator **hxxp://tempuri.org/Contract/MSValue1** as well as **MSValue1**, **MSValue2**, etc., whereas Redline Stealer will have **hxxp://tempuri.org/Entity/Id1.net** as well as Id1, Id2, etc. 

As for the binary, we can also look for Id*, MSValue*, Entity*, MSObject* patterns like in the screenshot below:

![comparison.png](/images/MetaStealer/comparison.png)

View of the Settings panel:
 ![panel_settings.jpg](/images/MetaStealer/panel_settings.JPG)

The Domain Detector settings are used to sort the logs out based on specific domains, the captured logs configured will be displayed as PDD (if the domain is found in credentials), CDD (if the domain is found in cookies) in the Logs panel as well as generated in the Logs file as DomainsDetected.txt.
The Misc section allows the user to clone the certificate of the binary and file information and apply it to the stealer build as well as to increase the file size and apply VirusTotal leak monitoring (to monitor if the file is submitted to VT).

![misc_panel.jpg](/images/MetaStealer/misc_panel.JPG)

Black Lists section allows the user to blacklist countries (it's worth noting that. compared to Redline, MetaStealer Stealer does not have an anti-CIS (Commonwealth of Independent States) feature) that prevents the stealer from running in CIS countries), IPs, HWIDs and build IDs. 

![panel_binder.jpg](/images/MetaStealer/panel_binder.JPG)

Binder/Crypt section allows the user to bind/merge binaries and obfuscate them with ConfuserEx. The user then can launch the merged binary from the disk or directly in memory with process hollowing using the following APIs:

- CreateProcessInternalW
- ZwUnmapViewOfsection
- ZwaAllocateVirtualMemory
- ZwWriteVirtualMemory
- ZwGetThreadContext
- LocalFree
- ZwSetContexThread
- ZwResumeThread
- ZwClose

We can test run the Yara rule that I provided at the end of this article for MetaStealer relying specifically on strings that are unique to MetaStealer on [unpac.me](https://www.unpac.me/yara/results/da81f160-887e-4284-bc17-b132c121c015). After the successful scan, we see 216 matches and 138 of them are detected as "Redline"

![yara_scan_Results.jpg](/images/MetaStealer/yara_scan_Results.JPG)

## Configuration Extractor

You can access the configuration extractor [here](https://github.com/RussianPanda95/Configuration_extractors/blob/main/metastealer_config_extractor.py)

{% highlight python %}

# Author: RussianPanda
import clr
import re
import base64

  
DNLIB_PATH = 'path_to_dnlib\\dnlib.dll'
clr.AddReference(DNLIB_PATH)

import dnlib
from dnlib.DotNet import *
from dnlib.DotNet.Emit import OpCodes

TARGET_PATH = 'path_to_binary'
module = dnlib.DotNet.ModuleDefMD.Load(TARGET_PATH)

def xor_data(data, key):

    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def extract_strings_from_dotnet(target_path):

    module = ModuleDefMD.Load(target_path)

    hardcoded_strings = []

    for t in module.Types:

        for m in t.Methods:

            if m.HasBody:

                for instr in m.Body.Instructions:

                    if instr.OpCode == OpCodes.Ldstr:

                        hardcoded_strings.append(instr.Operand)

    return hardcoded_strings


extracted_strings = extract_strings_from_dotnet(TARGET_PATH)

b64 = r'^[A-Za-z0-9+/]+={0,2}$'
b64_strings = []
last_b64_index = None

for i, string in enumerate(extracted_strings):

    if re.match(b64, string) and len(string) % 4 == 0 and len(string) > 20:

        b64_strings.append(string)

        last_b64_index = i

for i, string in enumerate(b64_strings):

    if i == 0:

        print("Authentication token:", string)

    else:

        break

xor_key = None

if last_b64_index is not None and last_b64_index + 1 < len(extracted_strings):

    print("Key:", extracted_strings[last_b64_index + 1])

    xor_key = extracted_strings[last_b64_index + 1].encode()

if xor_key:

    for string in b64_strings[1:]:  

        dec_Data = base64.b64decode(string)

        xor_result = xor_data(dec_Data, xor_key)

        try:

            final_result = base64.b64decode(xor_result)

            string_result = final_result.decode('utf-8')

            print("Decrypted String:", string_result)

        except Exception:

            pass

{% endhighlight %}

## Yara Rule

{% highlight liquid %}

import "pe"
rule MetaStealer {

	meta:
		author = "RussianPanda"
		decription = "Detects MetaStealer"
		date = "11/16/2023"

	strings:
		$s1 = "FileScannerRule"
		$s2 = "MSObject"
		$s3 = "MSValue"
		$s4 = "GetBrowsers"
		$s5 = "Biohazard"
			
	condition:
		4 of ($s*) 
		and pe.imports("mscoree.dll")
}

{% endhighlight %}

## Indicators of Compromise

| Name | Indicators                                                       |
| ---- | ---------------------------------------------------------------- |
| MetaStealer Sample   | 78a04c5520cd25d9728becca1f032348b2432a3a803c6fed8b68a8ed8cca426f |
|  MetaStealer Sample   | 1ab93533bff654a20fd069d327ac4185620beb243135640c2213571c8902e325 |
|  MetaStealer Sample   | 5f690cddc7610b8d4aeb85b82979f326373674f9f4032ee214a65758f4e479be |
|  MetaStealer Sample   | 65f76d89860101aa45eb3913044bd6c36c0639829f863a85f79b3294c1f4d7bb |
|  MetaStealer Sample   | c2f2293ce2805f53ec80a5f9477dbb44af1bd403132450f8ea421a742e948494 |
|  MetaStealer Sample   | 8502a5cbc33a50d5c38aaa5d82cd2dbf69deb80d4da6c73b2eee7a8cb26c2f71 |
|  MetaStealer Sample   | 727d823f0407659f3eb0c017e25023784a249d76c9e95a288b923abb4b2fe0dd |
|  MetaStealer Sample   | 941cc18b46dd5240f03d438ff17f19d946a8037fbe765ae4bc35ffea280df976 |
|  MetaStealer Sample   | 1a83b8555b2661726629b797758861727300d2ce95fe20279dec098011de1fff |
|  MetaStealer Sample   | c90a887fc1013ea0b90522fa1f146b0b33d116763afb69ef260eb51b93cf8f46 |
|  MetaStealer Sample   | 19034212e12ba3c5087a21641121a70f9067a5621e5d03761e91aca63d20d993 |
|  MetaStealer Sample   | 2db8d58e51ddb3c04ff552ecc015de1297dc03a17ec7c2aed079ed476691c4aa |
|  MetaStealer Sample   | de01e17676ce51e715c6fc116440c405ca4950392946a3aa3e19e28346239abb |


## References

[https://malpedia.caad.fkie.fraunhofer.de/details/win.metastealer](https://malpedia.caad.fkie.fraunhofer.de/details/win.metastealer)

[https://tria.ge/231027-nzmhssfg49/behavioral2](https://tria.ge/231027-nzmhssfg49/behavioral2)

[https://www.sentinelone.com/blog/macos-metastealer-new-family-of-obfuscated-go-infostealers-spread-in-targeted-attacks/](https://www.sentinelone.com/blog/macos-metastealer-new-family-of-obfuscated-go-infostealers-spread-in-targeted-attacks/)

[https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-redline-stealer](https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-redline-stealer)

[https://learn.microsoft.com/en-us/dotnet/api/system.servicemodel.channelfactory?view=dotnet-plat-ext-7.0](https://learn.microsoft.com/en-us/dotnet/api/system.servicemodel.channelfactory?view=dotnet-plat-ext-7.0)

[https://twitter.com/cod3nym](https://twitter.com/cod3nym)

[https://www.unpac.me/yara/results/da81f160-887e-4284-bc17-b132c121c015](https://www.unpac.me/yara/results/da81f160-887e-4284-bc17-b132c121c015)
