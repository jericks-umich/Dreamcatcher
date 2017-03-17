#!/bin/bash

FIFO_NAME=/tmp/checkpoint_fifo
TIMEOUT_NEW=300 # in seconds
TIMEOUT_EXPIRING=300 # in seconds

# create new fifo for message passing before we begin
rm -f $FIFO_NAME &>/dev/null
mkfifo $FIFO_NAME

# flush ebtables and create our default rules
ebtables -F
ebtables --new-chain arp_checkpoint
ebtables -A INPUT -p arp -j arp_checkpoint
ebtables -A FORWARD -p arp -j arp_checkpoint
ebtables -A arp_checkpoint --log --log-prefix ARP_CHECKPOINT --log-arp # default rule to log anything that isn't caught beforehand
ebtables -I arp_checkpoint --arp-src-ip 192.168.1.1 -j DROP # default rule to prevent router's ip from being stolen

# make subshell exit when main shell does
trap "kill 0" SIGINT

#  ___ _   _  ___ ___  _  _ ___ _    _
# / __| | | || _ ) __|| || | __| |  | |    
# \__ \ |_| || _ \__ \| __ | _|| |__| |__  
# |___/\___/ |___/___/|_||_|___|____|____| 
# SUBSHELL -- reads logread output, passes rule info to fifo for management
(
# open fifo
exec 3<>$FIFO_NAME # open r/w so when outer shell stops reading, it doesn't close
# read from logread and parse each line
logread -f -e ARP_CHECKPOINT | while read line
do
	# $line contains logged ARP_CHECKPOINT line -- parse out "IN" interface name and "ARP IP SRC" address
	text=$(echo "$line" | sed -r 's/.*IN=([a-z0-9]+\.[0-9]+).*ARP IP SRC=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*/\1 \2/')
	echo $text >&3
done
# close fifo
exec 3>&-
)& # background the subshell
# END OF SUBSHELL
#  ___  _  _  ___
# | __|| \| ||   \  
# | _| | .` || |) | 
# |___||_|\_||___/  


declare -A mapping # create "state" associative array
# keys will be ip addresses, values will be the interface names
# Example:
# mapping["192.168.1.189"] = "wlan0.101"
# mapping["192.168.1.187"] = "wlan0.100"

declare new # create queue of New-state IPs
declare expiring # create queue of Expiring-state IPs
# Values are a tuple in the form of <start time, IP>. Start time is in seconds since program start.
# both queues have the same format:
# ("127 192.168.1.187" "181 192.168.1.189" ... )
# the queues will always be ordered, with the next-to-expire at the front, and most-recently-updated at the back

function make_new {
	arp=$1
	iface=${arp[0]}
	ip=${arp[1]}

	# check if we have this mapping already
	if [[ ${mapping["$ip"]+1} ]] ; then
		# since we already have the mapping, check if its expiring and if so refresh it (if not, it might be a duplicate that slipped through)
		expiring_len=${#expiring[@]}
		for (( i=0; i<${expiring_len}; i++ )); # iterate over expiring entries
		do
			set ${expiring[$i]} # maps start time to $1 and IP to $2, for this expiring entry
			if [[ "$ip" == "$2" ]] ; then # if we've found an expiring IP, refresh it and break out of the loop
				# verify the mapping is still the same
				if [[ ${mapping["$ip"]} == "$iface" ]] ; then
					new+=("$SECONDS $ip") # refreshed entry into new queue
					expiring=("${expiring[@]:0:$i}" "${expiring[@]:$(expr $i + 1)}") # slice/concat expiring queue to remove element
					ebtables -I arp_checkpoint -i $iface --arp-src-ip $ip -j ACCEPT
				else # if the mapping is different, AHHHHHHHH!!!!!
					echo "ERROR: mapping is different!"
					old_iface=${mapping["$ip"]}
					echo "Existing mapping: $ip -> $old_iface"
					echo "New mapping: $ip -> $iface"
					# do not refresh mapping
				fi
				break # stop checking expiring queue for this IP
			fi
		done
	else # if we don't have this mapping
		# add this mapping and add its timestamp to the New queue
		mapping["$ip"]="$iface"
		new+=("$SECONDS $ip")
		# add new ebtables rules
		ebtables -I arp_checkpoint -i $iface --arp-src-ip $ip -j ACCEPT
		ebtables -I arp_checkpoint -i ! $iface --arp-src-ip $ip -j DROP
	fi
}

# check the timers for expiring and new arps and change state as appropriate
function check_timers {
	# check timers for expiring first, then new (and no, I can't figure out how to check them both with a loop -- bash is annoying)
	set ${expiring[0]} # maps start time to $1 and IP to $2, for this expiring entry
	while [[ "$(expr $SECONDS - $1)" -gt "$TIMEOUT_EXPIRING" ]] ; do
		# if this entry is expired, remove "drop" rule, remove mapping, shift expiring array to remove this entry
		ebtables -D arp_checkpoint -i ! ${mapping["$2"]} --arp-src-ip $2 -j DROP
		unset mapping["$2"]
		expiring=("${expiring[@]:1}") # slice off 0th element of array
		# re-set $1 and $2 at new start of expiring array
		set ${expiring[0]} # maps start time to $1 and IP to $2, for this expiring entry
	done
	set ${new[0]} # maps start time to $1 and IP to $2, for this new entry
	while [[ "$(expr $SECONDS - $1)" -gt "$TIMEOUT_NEW" ]] ; do
		# if this entry is expiring, remove "accept" rule, shift new array to remove this entry, and add new expiring entry
		ebtables -D arp_checkpoint -i ${mapping["$2"]} --arp-src-ip $2 -j ACCEPT
		new=("${new[@]:1}") # slice off 0th element of array
		expiring+=("$SECONDS $2")
		# re-set $1 and $2 at new start of new array
		set ${new[0]} # maps start time to $1 and IP to $2, for this new entry
	done
}

# sleep a bit to let the subshell get settled
sleep 1

# start the main loop
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
status=0
while : ; do # loop forever
	read -t 1 -a arp < $FIFO_NAME # timeout after 1 second so we can check timers even if there are no new arp packets to return us from read()
	status=$? # status of the read command. 0 is a successful read. Anything else is an error or a timeout (probably timeout).
	if [[ "$status" -eq "0" ]] ; then # if we got a new arp log
		make_new $arp
	fi
	# whether we got a new arp log or not, check the timers and change state as necessary
	check_timers
done


# wait for subshell to exit (never)
wait

echo "Quitting"
