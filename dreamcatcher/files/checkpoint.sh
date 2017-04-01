#!/bin/bash

ARP_FIFO_NAME=/tmp/arp_checkpoint_fifo
MAC_FIFO_NAME=/tmp/mac_checkpoint_fifo
ARP_TIMEOUT_NEW=300 # in seconds
ARP_TIMEOUT_EXPIRING=300 # in seconds
MAC_TIMEOUT_NEW=3000 # in seconds
MAC_TIMEOUT_EXPIRING=3000 # in seconds
# marked packets should *not* be logged
ARP_MARK=24 # mark value for ebtables packet marking -- hopefully doesn't conflict with any other marks
MAC_MARK=25 # mark value for ebtables packet marking -- hopefully doesn't conflict with any other marks
EBTABLES="ebtables --concurrent"

# create new fifo for message passing before we begin
rm -f $ARP_FIFO_NAME &>/dev/null
mkfifo $ARP_FIFO_NAME
rm -f $MAC_FIFO_NAME &>/dev/null
mkfifo $MAC_FIFO_NAME

# ╔╦╗╔═╗╔═╗╔═╗╦ ╦╦ ╔╦╗  ╦═╗╦ ╦╦  ╔═╗╔═╗
#  ║║║╣ ╠╣ ╠═╣║ ║║  ║   ╠╦╝║ ║║  ║╣ ╚═╗
# ═╩╝╚═╝╚  ╩ ╩╚═╝╩═╝╩   ╩╚═╚═╝╩═╝╚═╝╚═╝

# flush ebtables and create our default rules
$EBTABLES -F
$EBTABLES --new-chain arp_checkpoint -P RETURN
$EBTABLES -A INPUT -p arp -j arp_checkpoint
$EBTABLES -A FORWARD -p arp -j arp_checkpoint
$EBTABLES -A arp_checkpoint --mark ! $ARP_MARK -p arp --log --log-prefix ARP_CHECKPOINT --log-arp -j CONTINUE # default rule to log anything that isn't caught beforehand
$EBTABLES -I arp_checkpoint -p arp --arp-ip-src 192.168.1.1 -j DROP # default rule to prevent router's ip from being stolen
$EBTABLES --new-chain mac_log_checkpoint -P RETURN
$EBTABLES --new-chain mac_block_checkpoint -P RETURN
$EBTABLES -I INPUT -j mac_log_checkpoint
$EBTABLES -I FORWARD -j mac_log_checkpoint
$EBTABLES -I FORWARD -j mac_block_checkpoint # block should be before log (thus why it's second, since they're inserted)
$EBTABLES -A mac_log_checkpoint --mark ! $MAC_MARK --log --log-prefix MAC_CHECKPOINT -j CONTINUE # default rule to log anything that isn't caught beforehand

# make subshells exit when main shell does
trap "kill 0" SIGINT

# ╔╦╗╔═╗╔╦╗╔═╗  ╔═╗╔╦╗╦═╗╦ ╦╔═╗╔╦╗╦ ╦╦═╗╔═╗╔═╗
#  ║║╠═╣ ║ ╠═╣  ╚═╗ ║ ╠╦╝║ ║║   ║ ║ ║╠╦╝║╣ ╚═╗
# ═╩╝╩ ╩ ╩ ╩ ╩  ╚═╝ ╩ ╩╚═╚═╝╚═╝ ╩ ╚═╝╩╚═╚═╝╚═╝

declare -A arp_mapping # create "state" associative array
# keys will be ip addresses, values will be the interface names
# Example:
# arp_mapping["192.168.1.189"] = "wlan0.101"
# arp_mapping["192.168.1.187"] = "wlan0.100"

declare -A mac_mapping # create "state" associative array
# keys will be mac addresses, values will be the interface names
# Example:
# mac_mapping["00:11:22:33:44:55"] = "wlan0.101"
# mac_mapping["aa:bb:cc:dd:ee:ff"] = "wlan0.100"

declare arp_new # create queue of New-state IPs
declare arp_expiring # create queue of Expiring-state IPs
declare mac_new # create queue of New-state MACs
declare mac_expiring # create queue of Expiring-state MACs
# Values are a tuple in the form of <start time, IP/mac>. Start time is in seconds since program start.
# both queues have the same format:
# ("127 192.168.1.187" "181 192.168.1.189" ... )
# the queues will always be ordered, with the next-to-expire at the front, and most-recently-updated at the back

# ╔═╗╦ ╦╔╗╔╔═╗╔╦╗╦╔═╗╔╗╔╔═╗
# ╠╣ ║ ║║║║║   ║ ║║ ║║║║╚═╗
# ╚  ╚═╝╝╚╝╚═╝ ╩ ╩╚═╝╝╚╝╚═╝

function arp_make_new {
	arp=$1
	iface=${arp[0]}
	ip=${arp[1]}
	echo "New arp: $ip -> $iface"

	# check if we have this mapping already
	if [[ ${arp_mapping["$ip"]+1} ]] ; then
		echo "We already have this arp mapping"
		# since we already have the mapping, check if its expiring and if so refresh it (if not, it might be a duplicate that slipped through)
		expiring_len=${#arp_expiring[@]}
		for (( i=0; i<${expiring_len}; i++ )); # iterate over expiring entries
		do
			set ${arp_expiring[$i]} # maps start time to $1 and IP to $2, for this expiring entry
			if [[ "$ip" == "$2" ]] ; then # if we've found an expiring IP, refresh it and break out of the loop
				# verify the mapping is still the same
				if [[ ${arp_mapping["$ip"]} == "$iface" ]] ; then
					arp_new+=("$SECONDS $ip") # refreshed entry into new queue
					j=$(expr $i + 1)
					arp_expiring=("${arp_expiring[@]:0:$i}" "${arp_expiring[@]:$j}") # slice/concat expiring queue to remove element
					$EBTABLES -I arp_checkpoint -p arp -i $iface --arp-ip-src $ip -j mark --mark-set $ARP_MARK --mark-target CONTINUE
					echo "Refreshed arp expired -> new"
				else # if the mapping is different, AHHHHHHHH!!!!!
					echo "ERROR: arp mapping is different!"
					old_iface=${arp_mapping["$ip"]}
					echo "Existing mapping: $ip -> $old_iface"
					echo "New mapping: $ip -> $iface"
					# do not refresh mapping
				fi
				break # stop checking expiring queue for this IP
			fi
		done
	else # if we don't have this mapping
		echo "New arp mapping"
		# add this mapping and add its timestamp to the New queue
		arp_mapping["$ip"]="$iface"
		arp_new+=("$SECONDS $ip")
		# add new ebtables rules
		$EBTABLES -I arp_checkpoint -p arp -i ! $iface --arp-ip-src $ip -j DROP
		$EBTABLES -I arp_checkpoint -p arp -i $iface --arp-ip-src $ip -j mark --mark-set $ARP_MARK --mark-target CONTINUE
	fi
}

function mac_make_new {
	iface=$1
	mac=$2
	echo "New mac: $mac -> $iface"

	# check if we have this mapping already
	if [[ ${mac_mapping["$mac"]+1} ]] ; then
		echo "We already have this mac mapping"
		# since we already have the mapping, check if its expiring and if so refresh it (if not, it might be a duplicate that slipped through)
		expiring_len=${#mac_expiring[@]}
		for (( i=0; i<${expiring_len}; i++ )); # iterate over expiring entries
		do
			set ${mac_expiring[$i]} # maps start time to $1 and MAC to $2, for this expiring entry
			if [[ "$mac" == "$2" ]] ; then # if we've found an expiring IP, refresh it and break out of the loop
				# verify the mapping is still the same
				if [[ ${mac_mapping["$mac"]} == "$iface" ]] ; then
					mac_new+=("$SECONDS $mac") # refreshed entry into new queue
					j=$(expr $i + 1)
					mac_expiring=("${mac_expiring[@]:0:$i}" "${mac_expiring[@]:$j}") # slice/concat expiring queue to remove element
					$EBTABLES -I mac_log_checkpoint -i $iface -s $mac -j mark --mark-set $MAC_MARK --mark-target CONTINUE
					echo "Refreshed mac expired -> new"
				else # if the mapping is different, AHHHHHHHH!!!!!
					echo "ERROR: mac mapping is different!"
					old_iface=${mac_mapping["$mac"]}
					echo "Existing mapping: $mac -> $old_iface"
					echo "New mapping: $mac -> $iface"
					# do not refresh mapping
				fi
				break # stop checking expiring queue for this IP
			fi
		done
	else # if we don't have this mapping
		echo "New mac mapping"
		# add this mapping and add its timestamp to the New queue
		mac_mapping["$mac"]="$iface"
		mac_new+=("$SECONDS $mac")
		# add new ebtables rules
		$EBTABLES -I mac_block_checkpoint -o ! $iface -d $mac -j DROP
		$EBTABLES -I mac_log_checkpoint -i $iface -s $mac -j mark --mark-set $MAC_MARK --mark-target CONTINUE
	fi
}

# check the timers for expiring and new arps and change state as appropriate
function arp_check_timers {
	# check timers for expiring first, then new (and no, I can't figure out how to check them both with a loop -- bash is annoying)
	while [[ "${#arp_expiring[@]}" -gt "0" ]] ; do
		set ${arp_expiring[0]} # maps start time to $1 and IP to $2, for this expiring entry
		if [[ "$(expr $SECONDS - $1)" -lt "$ARP_TIMEOUT_EXPIRING" ]] ; then
			break
		fi
		echo "Expiring arp entry for $2 expired"
		# if this entry is expired, remove "drop" rule, remove mapping, shift expiring array to remove this entry
		$EBTABLES -D arp_checkpoint -p arp -i ! ${arp_mapping["$2"]} --arp-ip-src $2 -j DROP
		unset arp_mapping["$2"]
		arp_expiring=("${arp_expiring[@]:1}") # slice off 0th element of array
	done
	while [[ "${#arp_new[@]}" -gt "0" ]] ; do
		set ${arp_new[0]} # maps start time to $1 and IP to $2, for this new entry
		if [[ "$(expr $SECONDS - $1)" -lt "$ARP_TIMEOUT_NEW" ]] ; then
			break
		fi
		echo "New arp entry for $2 expiring"
		# if this entry is expiring, remove "accept" rule, shift new array to remove this entry, and add new expiring entry
		$EBTABLES -D arp_checkpoint -p arp -i ${arp_mapping["$2"]} --arp-ip-src $2 -j mark --mark-set $ARP_MARK --mark-target CONTINUE
		arp_expiring+=("$SECONDS $2")
		arp_new=("${arp_new[@]:1}") # slice off 0th element of array
	done
}

function mac_check_timers {
	# check timers for expiring first, then new (and no, I can't figure out how to check them both with a loop -- bash is annoying)
	while [[ "${#mac_expiring[@]}" -gt "0" ]] ; do
		set ${mac_expiring[0]} # maps start time to $1 and MAC to $2, for this expiring entry
		if [[ "$(expr $SECONDS - $1)" -lt "$MAC_TIMEOUT_EXPIRING" ]] ; then
			break
		fi
		echo "Expiring mac entry for $2 expired"
		# if this entry is expired, remove "drop" rule, remove mapping, shift expiring array to remove this entry
		$EBTABLES -D mac_block_checkpoint -o ! ${mac_mapping["$2"]} -d $2 -j DROP
		unset mac_mapping["$2"]
		mac_expiring=("${mac_expiring[@]:1}") # slice off 0th element of array
	done
	while [[ "${#mac_new[@]}" -gt "0" ]] ; do
		set ${mac_new[0]} # maps start time to $1 and MAC to $2, for this new entry
		if [[ "$(expr $SECONDS - $1)" -lt "$MAC_TIMEOUT_NEW" ]] ; then
			break
		fi
		echo "New mac entry for $2 expiring"
		# if this entry is expiring, remove "accept" rule, shift new array to remove this entry, and add new expiring entry
		$EBTABLES -D mac_log_checkpoint -i ${mac_mapping["$2"]} -s $2 -j mark --mark-set $MAC_MARK --mark-target CONTINUE
		mac_expiring+=("$SECONDS $2")
		mac_new=("${mac_new[@]:1}") # slice off 0th element of array
	done
}

# ╦  ╔═╗╔═╗╦═╗╔═╗╔═╗╔╦╗  ╔═╗╦ ╦╔╗ ╔═╗╦ ╦╔═╗╦  ╦  ╔═╗
# ║  ║ ║║ ╦╠╦╝║╣ ╠═╣ ║║  ╚═╗║ ║╠╩╗╚═╗╠═╣║╣ ║  ║  ╚═╗
# ╩═╝╚═╝╚═╝╩╚═╚═╝╩ ╩═╩╝  ╚═╝╚═╝╚═╝╚═╝╩ ╩╚═╝╩═╝╩═╝╚═╝
# SUBSHELL -- reads logread output, passes rule info to fifo for management
(
# open fifo
exec 3<>$ARP_FIFO_NAME # open r/w so when outer shell stops reading, it doesn't close
# read from logread and parse each line
logread -f -e ARP_CHECKPOINT | while read line
do
	# $line contains logged ARP_CHECKPOINT line -- parse out "IN" interface name and "ARP IP SRC" address
	arp_text=$(echo "$line" | sed -r 's/.*IN=([a-z0-9]+(\.[0-9]+)?).*ARP IP SRC=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*/\1 \3/')
	echo $arp_text >&3
done
# close fifo
exec 3>&-
)& # background the subshell

# SUBSHELL -- reads logread output, passes rule info to fifo for management
(
# open fifo
exec 4<>$MAC_FIFO_NAME # open r/w so when outer shell stops reading, it doesn't close
# read from logread and parse each line
logread -f -e MAC_CHECKPOINT | while read line
do
	# $line contains logged MAC_CHECKPOINT line -- parse out "IN" interface name and "MAC source" address
	mac_text=$(echo "$line" | sed -r 's/.*IN=([a-z0-9]+(\.[0-9]+)?).*MAC source = ([A-Za-z0-9]{2}:[A-Za-z0-9]{2}:[A-Za-z0-9]{2}:[A-Za-z0-9]{2}:[A-Za-z0-9]{2}:[A-Za-z0-9]{2}).*/\1 \3/')
	echo $mac_text >&4
done
# close fifo
exec 4>&-
)& # background the subshell

# sleep a bit to let the logread subshells get settled
sleep 1

# ╔╦╗╔═╗╦╔╗╔  ╦  ╔═╗╔═╗╔═╗╔═╗
# ║║║╠═╣║║║║  ║  ║ ║║ ║╠═╝╚═╗
# ╩ ╩╩ ╩╩╝╚╝  ╩═╝╚═╝╚═╝╩  ╚═╝
# start the main arp loop
# we're going to do two primary actions here
	# 1) read information from fifo (from log of arps) and create new rules to allow/block arp traffic
	# 2) monitor timers for rules and expire them periodically
		# non-expired rules have two states: New, and Expiring
		# when in the New state, a "rule" will consist of two ebtables rules, one "accept"ing arp packets from a particular interface with a given src ip, and one "drop"ing packets from all other interfaces with that same src ip
			# neither of these ebtables rules will log, and so this script will not see whether any packets match
			# over time, we will migrate rules individually into the "expiring" state, when a certain number of seconds have passed since the Rule was placed into the New state
		# when in the expiring state, the "accept" rule will be deleted, thus allowing any new valid arp packets to hit the default log rule
			# upon receiving a new arp for an existing rule, the state will move back to New, and the non-logging accept rule will be replaced
			# after a second timeout, if the rule is not moved back into the New state, it will be fully expired and the drop rule will be removed as well
(
status=0
while : ; do # loop forever
	read -t 1 -a arp < $ARP_FIFO_NAME # timeout after 1 second so we can check timers even if there are no new arp packets to return us from read()
	status=$? # status of the read command. 0 is a successful read. Anything else is an error or a timeout (probably timeout).
	if [[ "$status" -eq "0" ]] ; then # if we got a new arp log
		arp_make_new $arp
	fi
	# whether we got a new arp log or not, check the timers and change state as necessary
	arp_check_timers
done
)&

# this is the mac loop
# pretty similar to the arp loop above
(
status=0
while : ; do # loop forever
	read -t 1 mac < $MAC_FIFO_NAME # timeout after 1 second so we can check timers even if there are no new mac packets to return us from read()
	status=$? # status of the read command. 0 is a successful read. Anything else is an error or a timeout (probably timeout).
	if [[ "$status" -eq "0" ]] ; then # if we got a new mac log
		mac_make_new $mac
	fi
	# whether we got a new mac log or not, check the timers and change state as necessary
	mac_check_timers
done
)&

# ╔═╗╔╗╔╔╦╗
# ║╣ ║║║ ║║
# ╚═╝╝╚╝═╩╝

# wait for any subshell to exit (expected on error only)
#wait -n # openwrt's bash version doesn't support -n
wait # has to wait for all subshells ... oh well
kill 0 # kill any remaining subshells
echo "Error: Subshell exited early. Quitting..."


