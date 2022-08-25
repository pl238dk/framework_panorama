# Palo Alto Panorama Framework

This is a framework that connects to the API of Palo Alto Panorama firewall management system.

## Authentication

A username is required to be passed into the object, then `getpass()` will prompt for a password to authenticate in order to generate an API key from Panorama.

Subsequent calls to the Panorama will use the API key.

A function `authenticate()` will need to be invoked to authenticate to the appliance, afterward the X-PAN-KEY token will be used to remain authenticated.

## Getting Started

To instantiate a `PAN` object, pass a string of the server name :

```
>>> hostname = 'palo01.domain.com'
>>> p = PAN(host)
```

Then, to log into the appliance, invoke the `authenticate()` function :

```
>>> username = 'admin'
>>> p.authenticate(username)
```

## Palo Alto Panorama API Features

There are a tremendous amount of features available via API, similar to the Palo Alto firewall device API.

All functions are currently hard-coded to the VSYS1 device location, which should house all configurations by default for most setups.

Functions currently configured :
- Get Object Addresses
- Get Object Address Groups
- Get Object Regions
- Get Object Applications
- Get Object Application Groups
- Get Object Application Filters
- Get Object Services
- Get Object Service Groups
- Get Object Tags
- Get Object Global-Protect HIP Objects
- Get Object Global-Protect HIP Profiles
- Get Object External Dynamic Lists
- Get Object Custom Data Patterns
- Get Object Custom Spyware Signatures
- Get object Custom Vulnerability Signatures
- Get Object Custom URL Categories
- Get Object Antivirus Security Profiles
- Get Object Antispyware Security Profiles
- Get Object Vulnerability Protection Security Profiles
- Get Object URL Filtering Security Profiles
- Get Object File Blocking Security Profiles
- Get Object Wildfire Analysis Security Profiles
- Get Object Data Filtering Security Profiles
- Get Object DoS Protection Security Profiles
- Get Object Security Profile Groups
- Get Object Log Forwarding Profiles
- Get Object Log Forwarding Profiles
- Get Object Authentication Enforcements
- Get Object Decryption Profiles
- Get Object Decryption Forwarding Profiles
- Get Object Schedules
- Get Policy Security Rules
- Get Policy NAT Rules
- Get Policy QoS Rules
- Get Policy Policy-Based-Forwarding Rules
- Get Policy Decryption Rules
- Get Policy Tunnel Inspection Rules
- Get Policy Application Override Rules
- Get Policy Authentication Rules
- Get Policy DoS Rules
