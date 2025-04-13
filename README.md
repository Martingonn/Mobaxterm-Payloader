# Multi-Vector Attack Toolkit
A Python payload maker and deliverer that I originally made to test Mobaxterm servers, also tested on Metasploitable.
# What is it?
The code generates a payload that opens the target's shell and reveals passwords to the attacker. Has a series of prompts.
# Is it a trojan?!
Of course it isn't. Windows Defender flags it because of hexadecimal IP adress and payloads. To be clear, these payloads are not executed on attacker device. 
<br> Instead, they are send to the victim machine and executed there.
<br>If you do not trust me, simply examine the code. It does not connect to any external servers except the victim device whose adress YOU specify.
# Original Author 
Development was started on March 27th, 2025, by Marcin Jacek Chmiel.
# Contributors 
As of now, there are no more contributors than the original author.
If you have any problems or suggestions, contact me: *martingonn-dev@outlook.com*
# Disclaimer!!!
**Do not use the code in any illegal way!** I made it because my friend wanted me to test his Minecraft server.
# How to use
1. Download the files from the release you need.
2. Download required dependencies from the "required.txt" file using "pip install -r required.txt"
   **Make sure you have Npcap installed!**
4. Run the script, follow instructions in terminal.
   If Python tells you that you don't have required libraries installed even though you do, try running the script with "python" instead of "python3". Example: instead of "python3 payloader.py" do "python payloader.py"

# Future Additions
* one-line CLI launch
* more exploits (like screen takeover)
* allow for MAC-spoofing integration

# Downloads
![GitHub All Releases](https://img.shields.io/github/downloads/Martingonn/Multi-Vector-Attack-Toolkit/total)
