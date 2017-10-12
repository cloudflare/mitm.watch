
srcdir = $(CURDIR)/..
GOPHERJS := gopherjs

OBJS := public/jssock.js public/jssock.js.map \
	public/index.html public/socketapi.swf
# pre-compress to reduce latency
OBJS += public/jssock.js.gz public/jssock.js.map.gz

all: $(OBJS)
clean:
	$(RM) $(OBJS)
.PHONY: all clean

public:
	mkdir public

public/jssock.js public/jssock.js.map: $(srcdir)/main.go | public
	$(GOPHERJS) build -m -o public/jssock.js $<

public/index.html: $(srcdir)/index.html | public
	cp $< $@

public/socketapi.swf: $(srcdir)/SocketAPI.hx | public
	haxe -main SocketAPI -swf $@ -swf-version 13 -cp $(srcdir)

%.gz: %
	gzip -9k $<

