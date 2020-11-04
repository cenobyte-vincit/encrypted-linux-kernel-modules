# Checks the security of Mach-O 64-bit executables and application bundles
- Written and tested on macOS 10.15.7

## It is able to identify
- dyld injection vulnerabilities
- writable by others vulnerabilities
- missing stack canaries
- disabled PIE (ASLR)

## And it shows (targets of interest):
- setuid and setgid executables
- files and directories writable by others
- linking to non-existent dyld's (which potentially leads to dyld injection)

## Example 1 (on the Carbon Black macOS sensor):
```
$ ./machosec.sh /Applications/Confer.app
/Applications/Confer.app/ConferPerf.app/Contents/MacOS/python
├── no stack canary (missing '__stack_chk')
├── PIE (ASLR) disabled
├── linked to a non-system dylib: '/tmp/python/lib/libpython2.7.dylib'
└── /tmp/python/lib/libpython2.7.dylib does not exist
```

## Example 2 (on the readelf binary from Brew):
```
$ ./machosec.sh /usr/local/bin/greadelf
/usr/local/bin/greadelf
├── PIE (ASLR) disabled
└── not code signed
```
