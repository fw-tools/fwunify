#!/usr/bin/expect
spawn mn --topo single,2
expect ">"
send "py h1.setIP('10.0.0.10/24')\n"
expect ">"
send "py h2.setIP('200.19.0.100/24')\n"
expect ">"
send "h1 route add -net default h1-eth0\n"
expect ">"
send "h2 route add -net default h2-eth0\n"
expect ">"
send "h2 python -m SimpleHTTPServer 80 &\n"
expect ">"
send "xterm h1 h2\n"
interact