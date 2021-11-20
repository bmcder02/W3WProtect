# W3WProtect

During my time as an incident responder, IIS exploitation was the cause of most incidents that I responded too. The exploits were not inherently the same, but the resulting actions were always the same. The exploit would either: 

- Execute a process 

- Write to a file 

- Write to a registry key 

W3WProtect is a PoC that aims prevent exploitation by enforcing a whitelist around those three interactions. Specifically, we're able to enforce what processes, files and registry keys `w3wp.exe` can interact with. If it tries to do something it should, prevent it and write a log. 

A few features of W3WProtect:

    - Registry based config, with real-time updating. 
    - Passive/Enforced mode: Not comfortable with your config? Leave it in passive mode and only log interactions rather than block. 
    - ETW Support: Forward the logs to an EVTX file or straight into a host-based system (e.g. Velociraptor)
    - While I specifically focus on IIS, the same context could be used against any web service. 

# Disclaimer - Don't use this one your network!

This is just a proof of concept! While I will try to update bugs and add new features, this project is not a comercial product. This will likely BSOD your box in its current state. 

# Testing 

W3WProtect has currently been tested on the following OS's:

- Windows 10: v1905

If you've done any testing yourself on a different version, let me know! 

# Installation Guide

ToDo

# Configs 

ToDo

# Logging 

ToDo

# Future Goals

- Update process monitoring to also include command line. Allowing CMD to run if the command line arguments is in the whitelist. 