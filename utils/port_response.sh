#!/bin/bash
REMOTEHOST=200.19.0.100
REMOTEPORT=80
TIMEOUT=1

while :; do
   if nc -w $TIMEOUT -z $REMOTEHOST $REMOTEPORT; then
      echo "Connection to ${REMOTEHOST}:${REMOTEPORT} successful"
   else
       echo "Connection to ${REMOTEHOST}:${REMOTEPORT} failed."
   fi
sleep 5
done

