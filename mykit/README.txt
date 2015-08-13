Mykit - kernel level FreeBSD 8.2 rootkit

WARNING! This software was not widely tested, it can be UNSTABLE and may cause KERNEL PANIC and DATA LOSS!
PLEASE GET SURE YOU DON'T HAVE ANY IMPORTANT DATA ON YOUR PC BEFORE RUNNING IT!

WARNING! This software was designed for education and research purposes only!

Usage:
1. Build kernel module (make install)
2. Load kernel module 
# kldload mykit.ko
3. Build user modules
4. Use mycall to manage hidden files, connections, processes or get root and leet access
Leet access means ability to view any hidden objects

mycall
    -i Reload input conf files
    -c [hide|unhide]:laddr:lport:rport Hide a connection (local address port and remote port)
    -f [hide|unhide]:filename          Hide a file or a directory
    -l                                 Get leet (and give a shell)
    -n                                 Unleet
    -p [hide|unhide|ghost]:pid         Hide a process by pid 
(ghost means that process is invisible to system and doesn't handle signals from parent process)
    -r                                 Get root (and give a shell)
    -u                                 Unload mykit

Examples:
     mycall -c hide:0.0.0.0:22:52145
     mycall -f unhide:./leetfile
     mycall -p hide:6124