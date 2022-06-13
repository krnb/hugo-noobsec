---
title: "AD Enumeration"
date: 2022-06-12T00:36:33+05:30
aliases:
    - /powerview-cheatsheet
---

# AD Enumeration

This post assumes that opsec is not required and you can be as noisy as may be required to perform the enumeration. This post is meant for pentesters as well as defenders for the same reason - understand the AD environment better.

If you are looking for Pentester Academy's CRTP specific cheatsheet, it is [here](/crtp-cheatsheet)

> Note: Only a subset of flags and switches, which are most commonly used, are shared. Best documentation is the code itself.

> This is a living document. Last updated: 13 / June / 2022

## Get the Dog Out - SharpHound + BloodHound

Let's have the dog sniff things out because automated enumeration is cool

The tools used are - [BloodHound](https://github.com/BloodHoundAD/BloodHound/releases/), [SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) or [SharpHound.ps1]()

Leverage secure LDAP
``` powershell
./SharpHound.exe --SecureLdap
```

Getting all the data
``` powershell
./SharpHound.exe --CollectionMethod All
```

It's best to pull session info separately<br>
Gathering data in a loop (default 2hrs), makes sense for sessions as they change
``` powershell
./SharpHound.exe --CollectionMethod Session [--Loop] [--LoopDuration <HH:MM:SS>] [--LoopInterval <HH:MM:SS>]
```

Run in a different context
``` powershell
./SharpHound.exe --CollectionMethod All --LdapUsername <user_name> --LdapPassword <pass>
```

Specify domain
``` powershell
./SharpHound.exe -d this.domain.local --CollectionMethod All
```

Next step would be to take this data and then feed it to BloodHound GUI to finally have some fun :)

## Getting Hands Dirty - PowerView

Let's have some fun ourselves with manual enumeration.

We will use PowerView and some net commands to perform enumeration manually.

Assuming that latest PowerView script (master and dev are the same) has been loaded in memory.

### Domain Enumeration

Get basic information of the domain
``` powershell
Get-Domain
```

Get domain SID
``` powershell
Get-DomainSID
```

Get domain policies
``` powershell
Get-DomainPolicy [-Domain <target>]
```

Get domain Kerberos policy
``` powershell
(Get-DomainPolicy).KerberosPolicy
```

Get list of DCs
``` powershell
Get-DomainController [-Domain <target>]
```

Get DC IP
``` powershell
nslookup <target_dc>
```

### User Enumeration

Get a list of users
``` powershell
Get-NetUser [-Domain <target>] [user_name]
```

``` powershell
net user /domain
```

Get a count of users
``` powershell
(Get-NetUser).count
```

Get a list of users with some specific properties
``` powershell
Get-NetUser [-Properties <>] 
```

Get a list of users with their logon counts, bad password attempts where attempts are greater than 0
``` powershell
Get-NetUser | select cn, logoncounts, badpwdcount | ? {$_.badpwdcount -gt 0}
```

Finding users with SPN
``` powershell
Get-NetUser -SPN
```

Finding users who are AllowedToDelegateTo
``` powershell
Get-NetUser -TrustedToAuth
```

Finding users who can be delegated
``` powershell
Get-NetUser -AllowDelegation
```

### Computer Enumeration

Get a list of computers
``` powershell
Get-NetComputer [-Domain <target>] [-OperatingSystem "*2016*"] [-Properties <>]
```

Get a list of computers with Unconstrained delegation
``` powershell
Get-NetComputer -Unconstrained
```

Finding users who are AllowedToDelegateTo
``` powershell
Get-NetComputer -TrustedToAuth
```

### Group Enumeration

Get a list of groups in a domain
``` powershell
net group /domain
```

Get a list of groups in a domain
``` powershell
Get-NetGroup [-Domain <target>] [-FullData] [-GroupName "*admin*"] [-Username 'user_name']
```

Get group membership
``` powershell
Get-NetGroupMember [-GroupName 'group_name'] [-Recurse]
```

### Share Enumeration

List shares user have access to
``` powershell
Invoke-ShareFinder -CheckShareAccess -ErrorAction SilentlyContinue [-ComputerDomain <target_domain>]
```

### ACL Enumeration

Get resolved ACEs, optionally for a specific user/group and domain
``` powershell
Get-ObjectAcl [-Identity <user_name>] [-Domain <target_domain>] -ResolveGUIDs
```

Get interesting resolved ACLs
``` powershell
Invoke-ACLScanner [-Domain <target_domain>] -ResolveGUIDS
```

Get interesting resolved ACLs owned by specific object (ex. svcadmin)
``` powershell
Invoke-ACLScanner -ResolveGUIDS \| ?{$_.IdentityReference -match 'svcadmin'}
```

### Session Enumeration

Finding sessions on a computer
``` powershell
Get-NetSession [-Computer <comp_name>]
```

Get who is logged on locally where
``` powershell
Get-LoggedOnLocal [-ComputerName <comp_name>]
```

### User Hunting

Get list of machines where current user has local admin access
``` powershell
Find-LocalAdminAccess [-Domain <target_domain>]
```

Find machines where members of specific groups have sessions. Default: Domain Admins
``` powershell
Invoke-UserHunter [-GroupName <group_name>]
```

Find machines where current user has local admin access AND specific group sessions are present
``` powershell
Invoke-UserHunter -CheckAccess
```

