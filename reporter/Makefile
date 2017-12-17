GOBIN := go
FILES_CMD := git ls-files ':!*_test.go' ':!*/*' ':*.go' ':!generate_cert.go'
FILES := $(shell $(FILES_CMD))

reporter: $(FILES)
	$(GOBIN) build -o $@ $(FILES)

run:
	$(GOBIN) run $(FILES) $(ARGS)

watch:
	@type kqwait >/dev/null 2>&1 || kqwait(){ inotifywait -q -e delete_self,close_write "$$@"; }; \
	while :; do \
		files=$$($(FILES_CMD) | tr '\n' ' '); \
		echo "$$(date -R) - go run $$files"; \
		$(GOBIN) run $$files $(ARGS) & pid=$$!; \
		kqwait $$files >/dev/null; \
		kill $$(pgrep -P $$pid) $$pid; \
		sleep .1; \
	done

.PHONY: run watch
