#!/bin/bash

FIFO_NAME=/tmp/checkpoint_fifo

# create new fifo for message passing before we begin
rm -f $FIFO_NAME &>/dev/null
mkfifo $FIFO_NAME


#  ___ _   _  ___ ___  _  _ ___ _    _
# / __| | | || _ ) __|| || | __| |  | |    
# \__ \ |_| || _ \__ \| __ | _|| |__| |__  
# |___/\___/ |___/___/|_||_|___|____|____| 
# SUBSHELL -- reads logread output, passes rule info to fifo for management
(

# open fifo
exec 3<>$FIFO_NAME # open r/w so when outer shell stops reading, it doesn't close

count=0
while [[ "$count" -lt "10" ]]
do 
	echo "test $count" >&3 # write to fifo
	let "count += 1"
	sleep 1
done

# close fifo
exec 3>&-

)& # background the subshell
# END OF SUBSHELL
#  ___  _  _  ___
# | __|| \| ||   \  
# | _| | .` || |) | 
# |___||_|\_||___/  






# sleep a bit to let the subshell get settled
sleep 1

status=0
while [[ status -eq 0 ]]
do
	read -t 2 var_test < $FIFO_NAME
	status=$?
	echo "Status: $status"
	echo "Var: $var_test"
done



echo "Quitting"
