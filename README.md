# SRP_Automater
A tool that automates the creation of Software Restriction Polices

## Usage
Python SRP_Automater.py

## How it Works
SRP_Automater can be used to block binaries based on hashes. The script will query the filesystem for all instances of the said executable and create Software Restriction Policies to block them. 

## Use Case
This will help sysadmins and others who wish to block all instances of an executable. Windows will contain copies of binaries such as cmd.exe in several directories including system32, SysWoW64, WinSxS, and other misc. directories on the file system. Using this tool can help mitigate and prevent the abuse or bypassing of an SRP rule by ensuring all instances of the executable are blocked. 
