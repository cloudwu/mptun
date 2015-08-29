Multi-Path Tunnel VPN
=====================

It's a peer to peer VPN tunnel over UDP. You can specify multiple local ip if you have many gateway ,
and also can specify multiple remote ip . mptun can use all the possible paths for tunneling.

For example, if you have two internet connections , and you want to create one tunnel to your vps 
(it's very necessary in China :) over two of them , mptun can be helpful.

At server side  (your VPS) that has public IPs (SERVERIP) :

```
mptun -i tun0 -p PORT -v 10.0.0.2 -t 10.0.0.1 -k SECRET
```

At client side :

```
mptun -i tun0 -p PORT -v 10.0.0.1 -t 10.0.0.2 -r SERVER_IP1 -r SERVER_IP2 -l LOCAL_IP1 -l LOCAL_IP2 -k SECRET
```
You can also omit -l argument, for short 
```
mptun -i tun0 -p PORT -v 10.0.0.1 -t 10.0.0.2 -r SERVER_IP1 -k SECRET
```
Now you can testing the connection, ping -c 3 10.0.0.2 for details

The local ips only for sending package out (can be none public IP). 
if you specify multiple local ip , that means multiple paths to server.

-k specify the secret for authentication, it's optional but must be the same between server and client.

About Code
==========
The code is ugly, and just quick and dirty work for myself. It's not thoroughly tested, so of course there can be bugs. 
Any pull request is welcome, but don't ask me why the implementation is it :)

License
=======
The MIT License (MIT)

Copyright (c) 2015 codingnow.com

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

More Question ?
===============

Read the source code .












