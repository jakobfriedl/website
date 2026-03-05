---
title: 'Extending Conquest using Python Modules'
date: 2026-02-25T21:11:46+01:00

footer: 'Jakob Friedl © 2026' 

categories: ['c2-dev']
blog_post: true
draft: true
---

Command and control (C2) frameworks are sometimes also referred to as post-exploitation frameworks. This is because they enable their users to execute post-exploitation capabilities on compromised systems. To make the use of these capabilities as easy as possible, [**Conquest**,](https://github.com/jakobfriedl/conquest/) offers a advanced module system for extending the framework with Beacon Object Files or other third-party offensive tooling. This blog post showcases the creation of new commands using the Conquest Python API.  

<!--more-->

## The Bare Minimum

agent only contains the bare minimum of features
features that allow additional post-ex tools to be executed bof/dotnet
Enable-able to keep agent binary lightweight 

## Post-Exploitation using Beacon Object Files

what are Bofs
why bofs? 
examples for bofs

## Module System Architecture 

Python Scripting Engine
Script Manager
Modules vs. Commands vs. Command Groups

## Creating Commands

Name, Description, Example, Mitre techniques 
Arguments & Flags
Handler

### Python API Reference 

get_string()...

bof_pack           <--------------- Explain in detail 

execute_commands vs execute_alias 

Using python libraries in Conquest modules

## Example: scshell.py 