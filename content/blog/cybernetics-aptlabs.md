---
title: 'High-Level Red Team Training: Cybernetics & APTLabs Review'
date: 2024-01-27T22:24:39+02:00
draft: true

footer: 'Jakob Friedl © 2024' 

categories: ['hackthebox']
blog_post: true
---

A few months ago, I published a [blog post](/blog/offshore-rastalabs-zephyr) where I reviewed the first three HackTheBox Pro Labs that I completed in summer 2023: Offshore, RastaLabs and Zephyr. Over the winter months of this year, I took on the challenge to complete the two remaining advanced labs: Cybernetics and APTLabs. They are both rated as highly challenging, realistic and modern training environments for red team operators and penetration testers. In this blog post, I want to share the journey I went through while completing these labs with my good friend and colleague [Leo](https://leosmith.wtf/) and I'm going to give a brief review of the labs themselves and my opinion on them.

## Cybernetics: Advanced AD

 Being considered the "easier" lab of the two, Cybernetics was the first network that was tackled. This Red Team Operator Level 2 lab simulates a red team engagement against a massive and immersive corporate Active Directory environment. The lab is huge: 28 hosts, split up in 5 different domains and 25 distinct flags to collect while moving laterally through the network. As always, the end goal is to obtain Domain Admin privileges on all domains and collect the flags that are planted along the way. While there are a few web applications that are needed to be exploited to progress in the lab, most of the attacks in Cybernetics revolve around Active Directory exploitation, privilege escalation and lateral movement. A huge aspect of the lab which hadn't been covered in the previous ones is the usage of AD Certificate Services to issue certificates and use them for authentication. In order to log in to some of the machines, a valid certificate needs to be presented as a second authentication factor. I personally had to set up a secondary Windows virtual machine, which I used to request and store the certificates. Yet another interesting usage of this technology was the ability to request Code-Signing certificates to execute malicious code under a trusted signature. Cybernetics also simulates real users that are targeted through phishing attacks. The attacker is required to create a malicious document that is sent to the victim and then execute the payload on the victim's machine. Of course, the lab also includes it's fair share of Kerberos attacks, such as the classic resource-based constrained delegation attack, which had become a favourite of mine, as well as SQL Server attacks that exploit linked database servers on separated domains.

All in all, I would probably consider Cybernetics to be my favourite Pro Lab out of all of them, due to it's size, variety of attack vectors and the fact that is not frustratingly difficult, but still challenging enough to be learned from. Cybernetics required me to take my researching skills to the next level, working with technologies that I had never used or even heard of before. I had to improve my situational awareness and learn to keep track of all valuable information that was collected. For anyone interested in trying this lab, I highly recommend using a proper command and control framework, like [Havoc](https://github.com/HavocFramework/Havoc/), since it drastically simplifies managing compromised hosts, keeping persistence and provides built-in tools to move laterally. For note-taking, I personally use [Notion](https://www.notion.so/product), since it makes it easy for me to organize my notes based on hosts and domains, as well as to keep track of the credentials and flags that I have collected.

## APTLabs: Hardcore Threat Simulation

 Cybernetics was already quite a challenge, due to the variety of new attack vectors and technologies that I had not been familiar with. Little did I know how much harder the final lab was going to be. APTLabs takes it's name from the abbreviation APT, which stands for Advanced Persistent Threat. An APT is a group of highly skilled and motivated attackers that are usually sponsored by a nation state. They are known to be extremely stealthy and persistent, often staying in a network for months or even years without being detected. This Red Team Operator Level 3 lab simulates an attack of an external threat actor against the fictitious service provider Gigantic Hosting. The hosts in APTLabs are fully hardened, patched and are not exploitable using CVEs and exploits found on the Internet. Each of the 18 hosts in the lab could be considered a "Insane"-rated HackTheBox standalone machine. The network is split into 5 domains with their own Active Directory environment each. The goal is to obtain Domain Admin privileges wherever possible and collect the 20 flags that are placed throughout the network.

APTLabs requires a lot of enumeration, research and creativity. The lab is designed to be as realistic as possible, which means that there are plenty of modern defense mechanisms in place that restrict the freedom of the adversary. These security mechanisms include multi-factor authentication, AppLocker, JEA and many more. All attacks on the network are highly sophisticated and advanced, often requiring multiple steps to be chained together. For instance, there is a lot of focus set on relaying or spoofing attacks. This usually involves coercing authentication from one host to target, in order to compromise it or capturing credentials by utilising man-in-the-middle attacks. Plenty of Active Directory and Kerberos attack vectors are covered, but they usually include some sort of twist that changes the way the attack is performed, requiring some additional configuration or process. The TTPs (tactics, techniques and procedures) in this lab are incredibly interesting and useful for red teamers and penetration testers, since they target technologies and services that are widely used in modern corporate environments, like SCCM, ADFS or MSSQL.

It took me roughly 2 months to finish APTLabs. It was incredibly challenging and frustrating at times, but I have learning insanely much during the process. I had to learn to think outside the box and to be creative with the tools and techniques that I had at my disposal. I had to learn to be patient and to not give up, even if I was stuck on a machine for days. I had to learn to be organized and to keep track of all the information that I had collected. APTLabs pushed me outside of my comfort zone, but at the end of the day, there is nothing more rewarding than looking at that hard-earned certificate, knowing what it took to get it.

## Recommended Toolset

In this section, I want to provide a list of the tools that a used to most during my work on the HackTheBox Pro Labs so far. I have a [GitHub repository](https://github.com/jakobfriedl/precompiled-binaries), where I usually push compiled executables or scripts that I find useful. This repository also provides a well structured README and organizes the tools based on their intended use case. 

- **Havoc**: The most important tool in any red teamer's arsenal. Havoc is a command and control framework with a beautiful user interface and a flagship agent that made infecting machines during the labs a breeze. It provides a lot of useful tools to move laterally, keep persistence and manage compromised hosts, like the dotnet inline-execute command to execute .NET assemblies in memory.
- **ligolo-ng**: Ligolo-ng is a simple, lightweight and fast tool that allows penetration testers and red teamers to establish tunnels from a reverse TCP/TLS connection using a tun interface. It made pivoting between domains much easier and faster.
- **BloodHound**: BloodHound is an absolute necessity when it comes to Active Directory enumeration. It allows you to visualize the relationships between objects in an Active Directory environment, like trusts, ACLs and group memberships and find paths to escalate privileges and move laterally.
- **Rubeus**: There is no Active Directory without Kerberos and there is no Active Directory exploitation without Rubeus. Rubeus is a C# toolset that allows you to perform Kerberos attacks, like AS-REP Roasting, Kerberoasting, ticket attacks and many more. It is one of the most important tools in my arsenal and I used it on every single Windows machine during the labs.
- **SharpEfsPotato**: This tool is primarily used together with Havoc to escalate privileges on a machine, where the user has the SeImpersonatePrivilege privilege. More often than not, it was necessary to run commands with SYSTEM privileges, which was achieved by executing SharpEfsPotato with Havoc in memory.
- **PowerView**: PowerView is a collection of PowerShell functions that are used to perform Active Directory enumeration and exploitation. It is a must-have for any red teamer or penetration tester and is best used in combination with BloodHound.
- **Powermad**: Powermad is a toolset of PowerShell scripts that are used to perform DNS exploits, like adding and modifying ADIDNS nodes. Furthermore, it can be used to easily create new machine accounts in Active Directory, which is necessary to exploit RBCD. The tool was very frequently used in APTLabs and Cybernetics.
- **Impacket**: When no shell has been obtained on a machine, Impacket is the way to go. It is a collection of Python scripts that allow you to perform a variety of attacks against Windows machines, like SMB and MSSQL attacks, as well as AS-REP- and Kerberoasting. The incredible impacket-secretsdump command is used to dump the NTLM hashes of all users on a host or domain if a valid set of administrator credentials is provided.
- **CrackMapExec**: The Linux-based CrackMapExec (CME) allows you to perform Active Directory enumeration, as well as exploitation using it's module system. Particularly useful was the LAPS module, which allowed me to dump the local administrator password of a machine. I often used CME after compromising a user, to see if I could find any other machines that the user had access to.

> Edit: Instead of CrackMapExec, I now use it's successor [NetExec](https://github.com/Pennyw0rth/NetExec), which basically works the same way, but is more actively maintained and has a few additional features.

Remember, this is only a small selection of the tools that I used during the labs. I highly recommend checking out my [precompiled-binaries](https://github.com/jakobfriedl/precompiled-binaries) repository on Github, where I have compiled a list of all the tools that I used during the labs. I update this repository quite regularly, so make sure to star it if you find it useful.

## Conclusion

As already mentioned, Cybernetics and APTLabs elevated my knowledge on Active Directory enumeration and exploitation techniques, expanded my adversarial toolset and helped me develop situational awareness in complex environments. I am very grateful to have been able to complete them and to now consider myself a Level 3 Red Team Operator. The labs provide a challenge which I would recommend to anyone interested in advanced Active Directory attacks and are definitely worth the price. For more beginner- or intermediate-level difficulty, I would recommend the other Pro Labs, like Offshore and Zephyr, which I have reviewed in my previous blog post.