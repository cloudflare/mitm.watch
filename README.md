# TLS 1.3 in your web browser
This project is an experiment to run TLS 1.3 in a webbrowser with the intention
to check what kind of middleboxes ruin the game.

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
To enable TLS 1.3 client and server support, tls-tris master should work:

    export GOROOT=$(~/repos/tls-tris/_dev/go.sh env GOROOT)
    export GOPATH=$PWD/go
    PATH="${GOROOT/GOROOT/go}/bin:$GOPATH/bin:$PATH"
    go get github.com/gopherjs/gopherjs

The test target service requires a dummy certificate. If you have no valid
certificate for the reporter service, you can create it now as well with the
`-create-reporter=true` option. To do this:

    cd reporter
    go run generate_cert.go config.go models.go

During development, run these two commands separately to build the frontend and
to start the backend that provides tests:

    make -C server watch DEV=1
    make -C reporter watch

ALternatively, you can build once:

    make -C server DEV=1        # make frontend
    make -C reporter            # make backend with TLS 1.3 support
    cd reporter && ./reporter

To allow socket connections according to the the config file:

    cd server
    make caddy
    sudo ./caddy -type flashsocketpolicy -conf Caddyfile.flashsocketpolicy

(Alternatively, set the FlashListenAddress option which makes the reporter
daemon responsible for granting Flash socket access.)

To test, visit https://localhost:4433/ and open the Console tab in the Developer
Tools (tested with Chrome). Grant permission to use Flash and watch the logs.

## Configuration
The client configuration is located in `config_dev.go` (when built with `DEV=1`)
or `config_prod.go`. It contains the addresses for the reporter API.

The reporter API provides test cases and assists in execution of tests. Its
default configuration is in `reporter/config.go` but it can be overridden using
a configuration file. Missing keys will remain unchanged. Example:

    cd reporter
    ./reporter -writeconfig config_dev.json     # write default config and exit
    ./reporter -config config_dev.json          # run with config

Example where the configuration file is updated based on default values:

    echo '{"ListenAddress": ":443", "FlashListenAddress": ":587"}' > config_prod.json
    ./reporter -config config_prod.json -writeconfig config_prod.json

Note that the `-config` option is also valid for the `generate_cert.go` program.

## Bugs
Known limitations and issues:
- Requires click-to-play (user interaction).
- Flash is being killed, consider alternative methods. Non-options: Chrome
  socket API is limited to apps (which will be
  [removed](https://blog.chromium.org/2016/08/from-chrome-apps-to-web.html) in
  early 2018), FirefoxOS is also gone and the W3C TCP and UDP socket spec is
  also [abandoned](https://www.w3.org/2012/sysapps/).
- Certificate validation is missing.
- There are a lot of TODOs.
- Split socket API from main.go into a separate go package (jssock).
