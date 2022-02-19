# sshProxy
SSH over HTTP Websocket Proxy with SSL SNI Support

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
        
# Example use APP HTTP INJECTOR for Android 

Client:

  payload for HTTP
  
      GET / HTTP/1.1[crlf]Host: myserver.com[crlf]Upgrade: websocket[crlf][crlf]
        
   
   proxy
   
      ip: 192.168.1.10 / port: 80
      
      
Server:

  run terminal

       ./proxy -addr :80 -dstAddr 127.0.0.1:22
       
       
# For use SSL on mode STUNNEL

    Client:

      SNI: yourdomaintls.com

      SSH: 192.168.1.10

      Port: 443      
  
    Server:
       ./proxy -addr :80 -tls -tls_addr :443 -private_key /root/cert/fullchain.pem -public_key /root/cert/yourdomaintls.key