# TLS 1.3 in your web browser
This project is an experiment to run TLS 1.3 in a webbrowser with the intention
to check what kind of middle boxes ruin the game.

## Prototype
The [tris](https://github.com/cloudflare/tls-tris) library provides TLS 1.3
support (if this is not used, the application will be limited to TLS 1.2).

To support running Go in the web browser, the excellent
[gopherjs](https://github.com/gopherjs/gopherjs) is used.

The existing Fetch and XHR APIs only allow for some control over HTTP messages.
In order to experiment and gain insight over the TLS communication, control of
the TCP payload is required. This is (un)fortunately not possible in the context
of a webpage. Websockets cannot be used either since it starts with a HTTP
conversation and then follows with a custom framing. Therefore the first
prototype uses Adobe Flash to enable use of raw TCP sockets via its [Socket
API](http://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/net/Socket.html).

## Building
To build the Flash socket API file, [Haxe](https://haxe.org/) must be installed.
To enable TLS 1.3 client and server support, use the pwu/client branch of
tls-tris:

    export GOROOT=$(~/repos/tls-tris/_dev/go.sh env GOROOT)
    export GOPATH=$PWD/go
    PATH="${GOROOT/GOROOT/go}/bin:$GOPATH/bin:$PATH"
    go get github.com/gopherjs/gopherjs

During development of the frontend:

    ln -s ../.. "$GOPATH/src/jssock"
    gopherjs serve --http localhost:8080 -v

Otherwise one could create a minified config (see `Caddyfile`):

    cd server
    make DEV=1          # make frontend
    make caddy          # make server with TLS 1.3 support
    ./caddy -http-port 8080 -https-port 4433 -log stdout

To allow socket connections according to the the config file:

    cd server
    make caddy
    sudo ./caddy -type flashsocketpolicy -conf Caddyfile.flashsocketpolicy

To test, visit http://localhost:8080/jssock/ and open the Console tab in the
Developer Tools (tested with Chrome). Grant permission to use Flash and watch
the logs.

## Bugs
Known limitations and issues:
- Requires click-to-play (user interaction).
- Flash is being killed, consider alternative methods. Possible options include
  [chrome.socket.tcp](https://developer.chrome.com/apps/sockets_tcp), provided
  via a browser extension.
- Certificate validation is missing.
- There are a lot of TODOs.
- Split socket API from main.go into a separate go file
