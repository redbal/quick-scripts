#!/bin/bash

CMD="./client -c mycert.pem -h 127.0.0.1 -p 8443 -t 1.3 -z "

while read -r line 
  do 
     CCMD=$CMD$line
     echo $CCMD 
     echo $line >> ja3_capture.data
     eval $CCMD >> ja3_capture.data
     sleep 2
done < cipherstrings
