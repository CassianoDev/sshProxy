# sshProxy
SSH over HTTP Websocket Proxy with SSL SNI Support (up to 20 times faster than Python similar proxy and 100 times more users by CPU)

Tunnel for SSH with HTTP Websocket handler.

Usage:

-addr string

        Set port for listen clients. Ex.: 127.0.0.1:2086 (default ":2086")

-custom_handshake string

        Set HTTP code custom for response user. Ex.: 101/200.. etc.

-dstAddr string

        Set internal ip for SSH server redir. Ex.: 127.0.0.1:22 (default "127.0.0.1:22")

-private_key string

        Set path to your private certificate if use TLS. (default "/home/example/private.pem")

-public_key string

        Set path to your public certificate if use TLS. (default "/home/example/public.key")

-tls

        Set true to use TLS

-tls_addr string

        Set port for listen clients if use TLS mode. Ex.: 443 (default ":443")

-tls_mode
     
       Set TLS mode, if 'handshake' set, response  client with status 101/200 etc, if 'stunnel' set, not response client with status.


# Example use APP HTTP INJECTOR for Android

    Client Ex:
    payload for HTTP: 
        GET / HTTP/1.1[crlf]Host: myserver.com[crlf]Upgrade: websocket[crlf][crlf]
    proxy:
        ip: 192.168.1.10 / port: 80
    
    Server Ex:
        run terminal
            ./sshProxy -addr :80 -dstAddr 127.0.0.1:22


# For use SSL on mode STUNNEL

    Client Ex:
      SNI: yourdomaintls.com
      SSH: 192.168.1.10
      Port: 443      
  
    Server Ex:
       ./sshProxy -tls_mode "stunnel" -addr :80 -tls -tls_addr :443 -private_key /root/cert/fullchain.pem -public_key /root/cert/yourdomaintls.key

# For use SSL on mode SSL+HTTP PAYLOAD (for response 101/200...)

    Client Ex:
      SNI: yourdomaintls.com
      PAYLOAD: GET / HTTP/1.1[crlf][crlf]  
      SSH: 192.168.1.10
      Port: 443      
  
    Server Ex:
       ./sshProxy -tls_mode "handshake" -addr :80 -tls -tls_addr :443 -private_key /root/cert/fullchain.pem -public_key /root/cert/yourdomaintls.key
