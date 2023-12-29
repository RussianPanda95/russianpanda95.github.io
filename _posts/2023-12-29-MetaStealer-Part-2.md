---
layout: post
title: MetaStealer Part 2, Google Cookie Refresher Madness and Stealer Drama
description: MetaStealer Part 2 Malware Analysis
date: 2023-12-29 00:01:35 +0300
image: '/images/MetaStealerPart2/cookie_stealers.jpeg'
---

# Stealer's World of Drama

Previously, I wrote a blog going through some of MetaStealer's functionalities and did a brief comparison with Redline since they are both very similar but, at the same time, different. You might say that all stealers are the same because they have one purpose - to steal. However, each of them is somewhat different from the others, even if they borrowed the code from their predecessors. 

Every stealer tries to be better than the other one despite having similar code and functionality. What is considered a good stealer? The stealer has a low detection rate and a high rate of successful infection, or what we call "отстук" in Russian. Stealers such as Redline, Metastealer, Raccoon Stealer, Lumma, RisePro, and Vidar have earned their names in the stealer market. Below is the list of top stealers' whose logs are being sold on RussianMarket. 


![russianmarket.jpg](/images/MetaStealerPart2/russianmarket.JPG)

The popularity of mentioned stealers among users, mainly those developed by native Russian speakers, could be attributed to the ease of communication and support in their native language. As you might have noticed, stealers are notably prevalent among Russian-speaking communities. The ability to interact in one’s native language - whether it is to request new features, report issues, or inquire about the functionality of the stealer - significantly simplifies the process compared to the effort required for translation into English. This linguistic accessibility potentially broadens the client base, offering the stealer more opportunities to attract additional users.

The world of stealers is rife with drama, much like any other corner of the cybercriminal ecosystem. I was recently informed about an incident related to the Santa Barbara topic on XSS forums. This topic was created by one of Lumma's former coders, coinciding with Lumma's one-year anniversary. To put it briefly, Lumma's founder did not adequately recognize or compensate the coder's contributions, leading to dissatisfaction and underpayment.

![xss_post.jpg](/images/MetaStealerPart2/xss_post.JPG)

Another drama story: some of you might know how Aurora Stealer left the market before their infamous botnet release; some users deposited money for the botnet and never got it back, of course. Now, Aurora has become a meme within the stealer's community. 

In July 2023, an advertisement was posted on XSS forums for a new stealer written in Golang, known as "EasyStealer", then the rumors started spreading among the stealer's community that this was the work of an Aurora developer, now the stealer is nowhere to be found.  

![easystealer.jpg](/images/MetaStealerPart2/easystealer.JPG)

Does all of this impact the sales of stealers? Not at all. People continue to purchase stealers as long as their functionality meets their requirements.

# Google Cookie Refresher "feature" or a "0day"

So, you've likely heard about the [ongoing](https://x.com/g0njxa/status/1739689195403100336?s=20) Google "0day" vulnerability, which allows attackers to obtain fresh cookies, granting them "indefinite" access to Google accounts. It is a rather convenient "feature," isn't it? However, it is also quite dangerous because an attacker would be able to get fresh cookies to Google accounts each time the old ones expire.

![cookie.jpg](/images/MetaStealerPart2/cookie.jpg)

As @g0njxa [mentioned](https://x.com/g0njxa/status/1739658986113126721?s=20), the feature is abused by many stealers, including RisePro, MetaStealer, Whitesnake, StealC, Lumma, Rhadamanthys, and Meduza. Additionally, as of December 29th, Vidar Stealer has implemented this feature.

The question of how long it will take Google to respond to this issue remains unanswered. However, this situation presents even more opportunities for stealers to take advantage of the vulnerability. 

The reason why I brought this up is how easily it can be exploited with just a few lines of Python code that includes the decrypted token value, account ID, and the proper request to the server if some people are curious enough to find out. Although, certain parameters need to be slightly tweaked from the server's response to make it work. Here is my video with proof-of-concept on how it works on a high level. I have created a video demonstrating the proof-of-concept at a high level. For ethical reasons, I will not delve into the technical details of the POC.


<div class="embed-container">
  <iframe src="https://player.vimeo.com/video/898626856" width="700" height="480" frameborder="0" webkitallowfullscreen="" mozallowfullscreen="" allowfullscreen="">
  </iframe>
</div>

# MetaStealer Part 2: Technical Analysis

In November 2023, I released the [writeup](https://russianpanda.com/2023/11/20/MetaStealer-Redline's-Doppelganger/) on MetaStealer. However, soon after its release, the malware developer made another update that changed the class names, string encryption algorithm, binary description, and file icon. 

MetaStealer new version is approximately 368KB in size with the binary description **Cavils Corp. 2010** (the previous one was **METRO 2022 Dev**). 

The logo change:

![newlogo.png](/images/MetaStealerPart2/newlogo.png)

If previously, MetaStealer used "Entity" for class names; now it's using "Schema" and "TreeObject" to store data and configurations instead of **MSValue**.

![class_names_comp.jpg](/images/MetaStealerPart2/class_names_comp.JPG)

Instead of string replacement operations, it now accesses a decrypted string from an array based on the given index. For example, below, where it uses **ManagementObjectSearcher** class to query system management information. The constructor of **ManagementObjectSearcher** takes two parameters: a WMI query path and a query string, for example **"ROOT\SecurityCenter: SELECT * FROM AntivirusProduct"**.

![wmi_query.jpg](/images/MetaStealerPart2/wmi_query.JPG)

The new string decryption algorithm works the following way:
- First, the base64-encoded string gets base64-decoded and XOR'ed with the hardcoded key (in our example, it is **Crayfish**); the XOR'ed string then gets base64-decoded again. 

![str_dec_1.png](/images/MetaStealerPart2/str_dec_1.png)
- Each XOR'ed and base64-decoded string is assigned as an AES key and IV (Keys[1] and Keys[2]).

- The encrypted byte arrays are then reversed and decrypted using the keys and IV mentioned above

![str_dec_2.png](/images/MetaStealerPart2/str_dec_2.png)

To save us some time, we can use the dynamic approach to decrypt the strings using **dnlib**. The wonderful approach was detailed by @n1ghtw0lf in this [blog](https://n1ght-w0lf.github.io/tutorials/dotnet-string-decryptor/). Also, I want to thank [@cod3nym](https://twitter.com/cod3nym) for amazing tips when it comes to dealing with .NET shenanigans!

Here are the steps to decrypt the strings:

- We will use **dnlib**, a library for reading and writing .NET assemblies to load a .NET module and assembly from a given file path.

{% highlight python %}
def load_net_module(file_path):
    return ModuleDefMD.Load(file_path)

def load_net_assembly(file_path):
    return Assembly.LoadFile(file_path)
# Main script
module = load_net_module(file_path)
assembly = load_net_assembly(file_path)
{% endhighlight %}

- We will define the decryption signature (**decryption_signature**) to identify methods that are likely used for decryption. This signature includes the expected parameters and return type of the decryption methods.

{% highlight python %}
decryption_signature = [
    {"Parameters": ["System.Int32"], "ReturnType": "System.String"}
]
{% endhighlight %}

- We will search the loaded assembly for methods that match the defined decryption signature. 

{% highlight python %}
def find_decryption_methods(assembly):
    suspected_methods = []
    flags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic
    for module_type in assembly.GetTypes():
        for method in module_type.GetMethods(flags):
            for sig in decryption_signature:
                if method_matches_signature(method, sig):
                    suspected_methods.append(method)
    return suspected_methods
{% endhighlight %}

- Finally, we will invoke the suspected decryption methods by scanning the assembly's methods for calls to the suspected decryption methods, extracting the parameters passed to these methods, and invoking the decryption methods with the extracted parameters.

{% highlight python %}
def invoke_methods(module, suspected_methods):
    results = {}
    for method in suspected_methods:
        for module_type in module.Types:
            if not module_type.HasMethods:
                continue
            for m in module_type.Methods:
                if m.HasBody:
                    for insnIdx, insn in enumerate(m.Body.Instructions):
                        if insn.OpCode == OpCodes.Call:
                            called_method_name = str(insn.Operand)
                            if method.Name in called_method_name:
                                params = extract_parameters(m.Body.Instructions, insnIdx, method)
                                if len(params) == len(method.GetParameters()):
                                    try:
                                        result = invoke_method_safely(method, params)
                                        if result is not None:
                                            location = f"{module_type.FullName}.{m.Name}"
                                            results[location] = result
                                    except Exception as e:
                                        None
    return results
{% endhighlight %}

- We will also include the logic to handle different types of parameters, such as integers and strings. It uses **get_operand_value** to extract values from method instructions based on their type.

{% highlight python %}
def get_operand_value(insn, param_type):
    if "Int32" in param_type and insn.IsLdcI4():
        return Int32(insn.GetLdcI4Value())
    elif "String" in param_type and insn.OpCode == OpCodes.Ldstr:
        return insn.Operand
    return None
{% endhighlight %}

You can access the full script here. 

**Note:** Please run the script strictly in a sandbox environment.

The output of the script (tested on the deobfuscated sample *MD5: e6db93b513085fe253753cff76054a2a*):

![decrypted_strings.jpg](/images/MetaStealerPart2/decrypted_strings.JPG)

You might have noticed an interesting base64-encoded string in the output above. 

Upon decoding, we receive a .NET executable **qemu-ga.exe** (MD5: e6db93b513085fe253753cff76054a2a).

Now, an interesting moment: MetaStealer writes that executable to the Startup after successfully receiving the configuration from the C2 server and collecting user information. The executable does not do anything but enters the indefinite loop that alternates between sleeping for 100 seconds and waiting for user input without doing anything with that input. 

![qemu-ga.jpg](/images/MetaStealerPart2/qemu-ga.JPG)

Another addition to the new version of MetaStealer is the username and computer name check to avoid sandbox environments; if any of the usernames/computer names are found in the list, the stealer process will exit. 

List of computer names:

{% highlight xml %}
	{
		"bee7370c-8c0c-4", "desktop-nakffmt", "win-5e07cos9alr", "b30f0242-1c6a-4", "desktop-vrsqlag", "q9iatrkprh", "xc64zb", "desktop-d019gdm", "desktop-wi8clet", "server1",
		"lisa-pc", "john-pc", "desktop-b0t93d6", "desktop-1pykp29", "desktop-1y2433r", "wileypc", "work", "6c4e733f-c2d9-4", "ralphs-pc", "desktop-wg3myjs",
		"desktop-7xc6gez", "desktop-5ov9s0o", "qarzhrdbpj", "oreleepc", "archibaldpc", "julia-pc", "d1bnjkfvlh", "compname_5076", "desktop-vkeons4", "NTT-EFF-2W11WSS"
	};
{% endhighlight%}

List of usernames:

{% highlight xml %}
	{
		"wdagutilityaccount", "abby", "peter wilson", "hmarc", "patex", "john-pc", "rdhj0cnfevzx", "keecfmwgj", "frank", "8nl0colnq5bq",
		"lisa", "john", "george", "pxmduopvyx", "8vizsm", "w0fjuovmccp5a", "lmvwjj9b", "pqonjhvwexss", "3u2v9m8", "julia",
		"heuerzl", "harry johnson", "j.seance", "a.monaldo", "tvm"
	};
{% endhighlight%}

# Detection Rules

You can access Yara rules [here](https://github.com/RussianPanda95/Yara-Rules/tree/main/MetaStealer).

You can access Sigma rules [here](https://github.com/RussianPanda95/Sigma-Rules/blob/main/MetaStealer/suspicious_qemu_file_creation.yaml).


# Indicators of Compromise

| Name        | Indicator                            |
| ----------- | ------------------------------------ |
| MetaStealer | e6db93b513085fe253753cff76054a2a<br> |
| MetaStealer | a8d6e729b4911e1a0e3e9053eab2392b     |
| MetaStealer | b3cca536bf466f360b7d38bb3c9fc9bc     |
| C2            | 5.42.65[.]34:25530                                     |

For more samples, please refer to the result of my Yara scan on [UnpacMe](https://www.unpac.me/yara/results/f87b8452-ba6d-4c8b-8adb-1ba3986eb4d9#/).

![unpacme_results.jpg](/images/MetaStealerPart2/unpacme_results.JPG)


# Reference

[https://x.com/g0njxa/status/1739689195403100336?s=20](https://x.com/g0njxa/status/1739689195403100336?s=20)

[https://russianpanda.com/2023/11/20/MetaStealer-Redline's-Doppelganger](https://russianpanda.com/2023/11/20/MetaStealer-Redline's-Doppelganger/)

[https://n1ght-w0lf.github.io/tutorials/dotnet-string-decryptor](https://n1ght-w0lf.github.io/tutorials/dotnet-string-decryptor/)

[https://twitter.com/cod3nym](https://twitter.com/cod3nym)

[https://www.unpac.me/yara/results/f87b8452-ba6d-4c8b-8adb-1ba3986eb4d9#](https://www.unpac.me/yara/results/f87b8452-ba6d-4c8b-8adb-1ba3986eb4d9#/)

