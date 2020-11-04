#!/bin/bash
#
# machosec.sh
#
# Checks the security of Mach-O 64-bit executables and application bundles
#
# It is able to identify:
# - dyld injection vulnerabilities
# - writable by others vulnerabilities
# - missing stack canaries
# - disabled PIE (ASLR)
#
# And it shows (targets of interest):
# - setuid and setgid executables
# - files and directories writable by others
# - linking to non-existent dyld's (which potentially leads to dyld injection)
#
# Example 1 (on the Carbon Black macOS sensor):
# $ ./machosec.sh /Applications/Confer.app
# /Applications/Confer.app/ConferPerf.app/Contents/MacOS/python
# ├── no stack canary (missing '__stack_chk')
# ├── PIE (ASLR) disabled
# ├── linked to a non-system dylib: '/tmp/python/lib/libpython2.7.dylib'
# └── /tmp/python/lib/libpython2.7.dylib does not exist
#
# Example 2 (on the readelf binary from Brew):
# $ ./machosec.sh /usr/local/bin/greadelf
# /usr/local/bin/greadelf
# ├── PIE (ASLR) disabled
# └── not code signed
#
# Written and tested on macOS 10.15.7
#
# Tip: ls /Applications | while read x; do ./machosec.sh "/Applications/${x}"; done

readonly __progname="${BASH_SOURCE[0]}"
readonly PATH="/usr/sbin:/usr/bin:/sbin:/bin"

export output
export false="0"
export true="1"
readonly false
readonly true

usage() {
	echo -e "usage: ${__progname} <Mach-O executable / Application bundle>" >&2

	exit 1
}

errx() {
	echo -e "${__progname}: $*" >&2

	exit 1
}

addoutput() {
	[ -z "$1" ] && \
		return

	local tmp="$1"

	[ -z "${output}" ] || \
		tmp="$(echo -e "${output}\n$1")"

	output="${tmp}"
	tmp=""
}

perms() {
	if [ ! -e "$1" ]; then
		#echo "$1: does not exist" >&2
		addoutput "$1 does not exist"
		return
	fi

	# L(ow)
	stat -f "%SLp" "$1" | grep -q "w" && \
		addoutput "W_OTH flag set"

	# M(ed)
	stat -f "%SMp" "$1" | grep -q "s" && \
		addoutput "S_ISGID flag set"

	# H(igh)
	stat -f "%SHp" "$1" | grep -q "s" && \
		addoutput "S_ISUID flag set"
}

listdylibs() {
	otool -L "$1" 2>/dev/null | \
		grep '\t' | \
		tr -d '\t' | \
		cut -d '(' -f 1 | \
		grep '^/' | \
		sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/[[:space:]]/,/'
}

listnonsysdylibs() {
	local SAVEIFS="${IFS}"
	local IFS="$(echo -en "\n\b")"

	for dylib in $(listdylibs "$1" | egrep -v "^/System/|^/usr/lib/|^/Library/"); do
		[ -z "${dylib}" ] && \
			continue

		addoutput "linked to a non-system dylib: '${dylib}'"

		# dyld's can also be linked, so check whether there is something wrong with those sub-dyld's
		# but just exclude the ones in /Applications
		for subdylib in $(listdylibs "${dylib}" | egrep -v "^/System/|^/usr/lib/|^/Library/|^/Applications/" | grep -vw "${dylib}"); do
			[ -z "${subdylib}" ] && \
				continue

			addoutput "'${dylib}' is linked to a non-system dylib: '${subdylib}'"
			perms "${subdylib}"
		done
	done

	local IFS="${SAVEIFS}"
}

vulndylibs() {
	local SAVEIFS="${IFS}"
	local IFS="$(echo -en "\n\b")"

	for dylib in $(listdylibs "$1"); do
		perms "${dylib}"
	done

	local IFS="${SAVEIFS}"
}

canarycheck() {
	otool -Iv "$1" 2>/dev/null | \
		grep -q "__stack_chk" || \
			addoutput "no stack canary (missing '__stack_chk')"
}

codesigned() {
	codesign -vvvv "$1" 2>&1 | \
		grep -q "code object is not signed at all" && \
			addoutput "not code signed"
}

pie() {
	otool -hv "$1" 2>/dev/null | grep -qw PIE || \
		addoutput "PIE (ASLR) disabled"
}

checkmacho() {
	export output=""
	addoutput "$1"

	canarycheck "$1"
	pie "$1"
	perms "$1"
	listnonsysdylibs "$1"
	vulndylibs "$1"
	codesigned "$1"

	print

	return 0
}

checkappbundle() {
	perms "$1"

	SAVEIFS="${IFS}"
	IFS="$(echo -en "\n\b")"

	for wothent in $(find "$1" -perm -o+w 2>/dev/null); do
		addoutput "'${wothent}' W_OTH flag set"
	done

	for appent in $(find "$1"); do
		file "${appent}" 2>/dev/null | grep -qw "Mach-O 64-bit executable" && \
			checkmacho "${appent}"
	done

	IFS="${SAVEIFS}"

	return 0
}

print() {
	# nothing to print
	[ -z "${output}" ] && \
		return

	len="$(echo "${output}" | wc -l | tr -d ' ')"
	[[ "${len}" -eq 1 ]] && \
		return

	# ready for JSON output mode
	i=1
	echo "${output}" | while read line; do
		if [ "${i}" == 1 ]; then
			# start
			echo "${line}"
		elif [ "${i}" == "${len}" ]; then
			# finish
			echo -e "└── ${line}\n"
		else
			echo "├── ${line}"
		fi

		((i++))
	done

	export output=""
}

main() {
	[[ "$#" -ne 1 ]] && \
		usage

	for bin in codesign otool file; do
		command -v "${bin}" >/dev/null 2>&1 || \
			errx "cannot find '${bin}' in 'PATH=${PATH}'"
	done

	# remove trailing slash
	local ent="${1%/}"
	[ ! -e "${ent}" ] && \
		errx "cannot open '${ent}'"

	if [ -f "${ent}" ]; then
		readonly ent
		file "${ent}" 2>/dev/null | grep -qw "Mach-O 64-bit executable"
		[ $? -ne 0 ] && \
			errx "'${ent}' is not a Mach-O 64-bit executable"

		checkmacho "${ent}"
	elif [ -d "${ent}" ]; then
		if [ ! -d "${ent}/Contents/MacOS" ]; then
			# Some Adobe products have a nested .app directory
			local tmp="$(ls "${ent}/" | grep '\.app' | head -1)"
			[ -z "${tmp}" ] && \
				errx "'${ent}' is not an application bundle"

			readonly ent="${ent}/${tmp}"
		fi

		checkappbundle "${ent}"
	fi

	return 0
}

main "$@"
