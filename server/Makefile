
srcdir = $(CURDIR)/..
GOPHERJS := gopherjs
CADDY_GOPATH := $(CURDIR)/go

OBJS := public/index.html public/jssock.js public/socketapi.swf
# pre-compress to reduce latency
OBJS += public/jssock.js.gz
DEV_OBJS := public/jssock.js.map public/jssock.js.map.gz public/main.go
ifeq ($(DEV),1)
OBJS += $(DEV_OBJS)
endif

all: $(OBJS)
clean:
	$(RM) $(OBJS) $(DEV_OBJS)
.PHONY: all clean

public:
	mkdir public

ifeq ($(DEV),1)
CONFFILE := $(srcdir)/config_dev.go
else
CONFFILE := $(srcdir)/config_prod.go
endif

public/jssock.js public/jssock.js.map: $(srcdir)/main.go $(CONFFILE) | public
ifeq ($(DEV),1)
	$(GOPHERJS) build -o public/jssock.js $^
else
	$(GOPHERJS) build -o public/jssock.js $^ -m --tags prod
	sed -e '/sourceMappingURL=/d' -i '' public/jssock.js
	$(RM) public/main.go public/jssock.js.map public/jssock.js.map.gz
endif

public/index.html: $(srcdir)/index.html | public
	cp $< $@

public/socketapi.swf: $(srcdir)/SocketAPI.hx | public
	haxe -main SocketAPI -swf $@ -swf-version 13 -cp $(srcdir)

public/main.go: $(srcdir)/main.go | public
	cp $< $@

%.gz: %
	gzip -9kf $<

magic := 'This is where other plugins get plugged in'
insert := '_ "flashsocketpolicy"'
caddydir := $(CADDY_GOPATH)/src/github.com/mholt/caddy/caddy
$(caddydir):
	GOPATH=$(CADDY_GOPATH) go get github.com/mholt/caddy/caddy
	# Expect line to insert out import after; then insert if missing
	grep -q $(magic) $(caddydir)/caddymain/run.go
	grep -q $(insert) $(caddydir)/caddymain/run.go || \
		sed -e "$$(printf '/%s/a\\\n%s' $(magic) $(insert))" -i '' $(caddydir)/caddymain/run.go

caddybuildsdir := $(CADDY_GOPATH)/src/github.com/caddyserver/builds
$(caddybuildsdir):
	GOPATH=$(CADDY_GOPATH) go get github.com/caddyserver/builds

$(CADDY_GOPATH)/src/flashsocketpolicy/server.go: server.go
	mkdir -p $(dir $@)
	cp server.go $@

caddy: $(CADDY_GOPATH)/src/flashsocketpolicy/server.go \
	$(caddydir) $(caddybuildsdir)
	cd $(caddydir) && GOPATH=$(CADDY_GOPATH) go run build.go
	mv $(caddydir)/caddy $@
