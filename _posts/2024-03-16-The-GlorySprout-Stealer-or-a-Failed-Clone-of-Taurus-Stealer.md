---
layout: post
title: The GlorySprout or a Failed Clone of Taurus Stealer
description: GlorySprout malware analysis
date: 2024-03-16 15:01:35 +0300
image: '/images/GlorySprout/beansprout.jpeg'
---
# Case Study

The GlorySprout ads surfaced on the XSS forum at the beginning of March 2024 (the name makes me think of beansprout; perhaps the seller behind the stealer is a vegetarian).

![XSSads.jpg](/images/GlorySprout/XSSads.JPG)

The stealer, developed in C++, is available for purchase at $300, offering lifetime access and 20 days of crypting service, which encrypts the stealer's payload to evade detection. Similar to other stealers, it includes a pre-built loader, Anti-CIS execution, and a Grabber module (which is non-functional). While the stealer advertises AntiVM and keylogging capabilities, I have not witnessed either in action or code. Additionally, it features support for log backup and log banning, allowing for the exclusion of logs from specified countries or IPs.

What particularly captured my attention regarding this stealer was that an individual, who prefers to stay anonymous, informed me it's a clone of Taurus Stealer and shared some interesting files with me.

# Taurus Stealer Backstory

Let's a little about Taurus Stealer Project. It first appeared for sale on XSS in April 2020.  

![taurusads.jpg](/images/GlorySprout/taurusads.JPG)

The stealer is written in C++ with a Golang panel. It was sold for $150 for lifetime (I guess the pricing was different in 2020). 

One of the XSS users claims that the panel is very similar to Predator The Thief stealer. You can read a nice writeup on Predator Stealer [here](https://fumik0.com/2019/12/25/lets-play-again-with-predator-the-thief/).

![xsscomment.jpg](/images/GlorySprout/taurusads.JPG)

The Predator stealer shares many similarities with Taurus Stealer, including encryption in C2 communication, Bot ID formatting, the Anti-VM feature, and naming conventions for log files, as well as resemblances in the panel GUI. However, to refocus, Taurus Stealer terminated their project around 2021. The cracked version of Taurus Stealer is being sold on Telegram, and there's information suggesting that Taurus Stealer sold their source code, which could explain these parallels.

Now, let's confirm the theories...

Below is the screenshot of GlorySprout panel:

![panel.jpg](/images/GlorySprout/taurusads.JPG)

And this is the Taurus Stealer panel:

![tauruspanel.jpg](/images/GlorySprout/taurusads.JPG)

Can you spot the similarities and differences? :)

There is a great writeup on Taurus Stealer out there by Outpost24 that you can access [here](https://outpost24.com/blog/an-in-depth-analysis-of-the-new-taurus-stealer/).

I will focus on the brief analysis of GlorySprout so we can make some conclusions later. 

# GlorySprout Technical Analysis

GlorySprout dynamically resolves APIs through API hashing, targeting libraries such as shell32.dll, user32.dll, ole32.dll, crypt32.dll, advapi32.dll, ktmw32.dll, and wininet.dll. This hashing process involves operations such as multiplication, addition, XOR, and shifting.

![api_hashing.jpg](/images/GlorySprout/api_hashing.JPG)

The reproduced Python code for API hashing:

{% highlight python %}
def compute_hash(function_name):
    v9 = 0
    for char in function_name:
        v9 = ord(char) + 16 * v9
        if v9 & 0xF0000000 != 0:
            v9 = ((v9 & 0xF0000000) >> 24) ^ v9 & 0xFFFFFFF
    return v9
{% endhighlight %}

The stealer accesses the hashed API values via specific offsets.

![accessing_api.png](/images/GlorySprout/accessing_api.png)

![[api_hashing2 1.png]]

The Anti-CIS function is shown below:

![antiCIS.jpg](/images/GlorySprout/antiCIS.JPG)

The stealer exists if any of the language identifiers is found. 

The stealer obfuscates the strings via XOR and arithmetic operations such as substitution.  

![str_obfuscation.png](/images/GlorySprout/str_obfuscation.png)

The persistence is created via scheduled task named **\WindowsDefender\Updater** with ComSpec (cmd.exe) spawning the command **/c schtasks /create /F /sc minute /mo 1 /tn \"\\WindowsDefender\\Updater\" /tr \"**. If the loader module is used, the task runs the dropped secondary payload from **%TEMP%** folder.

![scheduled_task.jpg](/images/GlorySprout/scheduled_task.JPG)

If the loader module is configured, the retrieved payload name (8 characters) would be randomly generated via the function below from the predefined string **aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ**. 

![rand_gen.jpg](/images/GlorySprout/rand_gen.JPG)

The function described is also used to generate the **filename** parameter in a Content-Disposition header for C2 communications as well as the RC4 key for the ZIP archive with collected data.

But the function to generate random string doesn't always generate random strings and we will come back to it in the C2 communications section. 

The C2 address of the stealer is retrieved from the resource section of the decrypted/unpacked payload.

![get_c2.png](/images/GlorySprout/get_c2.png)

# C2 Communications

Communication with the C2 server is performed via port 80. Upon checking in with the C2 server, the infected machine sends out the POST request **/cfg/data=<BotID>**using the user-agent **Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit / 537.36 (KHTML, like Gecko) Chrome / 83.0.5906.121 Safari/537.36**. The BotID value is encrypted with the RC4 key generated via random key generation function that was previously mentioned and base64-encoded. The RC4 key is the first 10 bytes of the encrypted string. 

![c2_post_check_in.jpg](/images/GlorySprout/c2_post_check_in.JPG)

The base64-encoding set of characters is obfuscated as shown below.

![base64_enc.jpg](/images/GlorySprout/base64_enc.JPG)

Now, interestingly enough, the RC4 key for the initial check-in does not change depsite using the randomization, because the initial state value remains constant, which is **0xC40DF552**. If we try the randomization function with Python and using the initial state value, we get the same value, which is **IDaJhCHdIlfHcldJ**. 

The reproduced Python code for randomization function:

{% highlight python %}

initial_seed = 0xC40DF552  # Initial state for the rand() function

src_data = bytes.fromhex("1B6C4C6D4D6E4E6F4F70507151725273537454755576567757785879597A5A7B5B7C5C7D5D7E5E7F5F80608161826283")

adjusted_src_data = bytearray(len(src_data))
for i, b in enumerate(src_data):
    adjusted_src_data[i] = b - (src_data[0] % 16)

def rand(seed):
    seed = (214013 * seed + 2531011) & 0xFFFFFFFF  
    return ((seed >> 16) & 0x7FFF), seed  

# Generate the key
def generate_key(a2, seed):
    key = ""
    for _ in range(a2):
        rand_val, seed = rand(seed)
        key += chr(adjusted_src_data[1 + (rand_val % 23)]) 
    return key, seed

# Generate the RC4 key with a2 = 0x10 and the initial seed
value, final_seed = generate_key(0x10, initial_seed)
value, final_seed

print(value)

{% endhighlight %}

After the check-in, the server responds with an encrypted configuration, where the first 10 bytes is the RC4 key.

The decrypted conguration looks like this:

{% highlight xml %}
[1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;0;0;1;1]#[]#[<infected_machine_IP;<infected_machine_GEO]#[[<loader_URL;;;1;1;1]]
{% endhighlight %}


Here is an example breakdown of the configuration:
- 1: Grab browser history 
- 1: Grab screenshot
- 1: Grab cryptowallets recursively from %AppData% folder (Cryptowallets supported based on the analysis: Electrum, MultiBit, Armory, Ethereum, Bytecoin, Jaxx, Atomic, Exodus, DashCore, Bitcoin, WalletWasabi, Daedalus Mainnet, Monerom )
- 1: Grab Steam sessions
- 1: Grab BattleNet account information
- 1: Grab Telegram session
- 1: Grab Discord session
- 1: Grab Skype messages
- 1: Grab Jabber accounts from %AppData% folder
- 1: Grab Foxmail accounts
- 1: Grab Outlook accounts
- 1: Grab FileZilla data
- 1: Grab WinFTP accounts
- 1: Grab WinSCP accounts
- 1: Grab Authy
- 0: Grab NordVPN
- 0: Unknown placeholder
- 1: Anti-VM
- 1: Self-deletion (self-delete after sending the logs to C2): self-deletion performs with the command **C:\Windows\system32\cmd.exe" /c ping google.com && erase C:\Users\<username>\Desktop\<stealer>.exe** . Pinging introduces the delay, likely to guarantee the successful full execution of the payload.
- loader_URL - contains the link to the secondary payload
- 1: Only with crypto - the loader payload only runs if cryptowallets are present on the machine
- 1: Autorun - creates the persistence for a secondary payload
- 1: Start after creating - runs the secondary payload after dropping it in %TEMP% folder

After receiving the configuration, the infected machine sends out the POST request with **/log/** parameter containing the ZIP archive with collected data to C2 server as shown below:

![send_zip_c2.jpg](/images/GlorySprout/send_zip_c2.JPG)

The data is encrypted the same way, with RC4 and Base64-encoded.

The server sends **200 OK** response to the machine and the machine ends the communication with the POST request containing **/loader/complete/?data=1** . 

# Additional Information

As mentioned before, the panel of the stealer is written in Golang. The panel also utilizes SQL databases to process configuration and data. The stealer makes use of **sqlx** library, a popular extension for Go's standard **database/sql** package designed to make it easier to work with SQL databases. 

![golang_p.jpg](/images/GlorySprout/golang_p.JPG)

The usernames found in mysql database:

![sql_db.png](/images/GlorySprout/sql_db.png)

It's worth nothing that the database contains the mention of **taurus**. At this point, we can make a confident assessment that it's a clone of Taurus Stealer code based on the technical analysis. 

The example of the collected log:

![info.jpg](/images/GlorySprout/info.JPG)

General/forms.txt - contains the decrypted browser passwords. The browser passwords are decrypted on the server. 

# Conclusion

Based on the GlorySprout analysis, it is confidently assessed that the individual behind GlorySprout cloned the code of the Taurus Stealer project and modified it according to their specific needs and requirements. A notable difference is that GlorySprout, unlike Taurus Stealer (according to the version analyzed by Outpost24), does not download additional DLL dependencies from C2 servers. Additionally, GlorySprout lacks the Anti-VM feature that is present in Taurus Stealer. GlorySprout is likely to fade away e and fail to achieve the popularity of other stealers currently on the market.

# Indicators Of Compromise

| Name | Indicators |
| ---- | ---- |
| GlorySprout | 3952a294b831e8738f70c2caea5e0559 |
| C2 | 147.78.103.197 |
| C2 | 45.138.16.167 |
| GlorySprout | d295c4f639d581851aea8fbcc1ea0989 |

# Detection

You can access the Yara rule [here](https://github.com/RussianPanda95/Yara-Rules/blob/main/GlorySprout/win_mal_GlorySprout_Stealer.yar)

# References

[https://fumik0.com/2019/12/25/lets-play-again-with-predator-the-thief/](https://fumik0.com/2019/12/25/lets-play-again-with-predator-the-thief/)
[https://outpost24.com/blog/an-in-depth-analysis-of-the-new-taurus-stealer/](https://outpost24.com/blog/an-in-depth-analysis-of-the-new-taurus-stealer/)
[https://github.com/RussianPanda95/Yara-Rules/blob/main/GlorySprout/win_mal_GlorySprout_Stealer.yar](https://github.com/RussianPanda95/Yara-Rules/blob/main/GlorySprout/win_mal_GlorySprout_Stealer.yar)

