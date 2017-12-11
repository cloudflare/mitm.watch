GOBIN := go
FILES_CMD := git ls-files ':!*_test.go' ':!*/*' ':*.go'
FILES := $(shell $(FILES_CMD))

run:
	go run $(FILES)

watch:
	@while :; do \
		files=$$($(FILES_CMD) | tr '\n' ' '); \
		echo "$$(date -R) - go run $$files"; \
		$(GOBIN) run $$files & pid=$$!; \
		kqwait $$files >/dev/null; \
		kill $$(pgrep -P $$pid) $$pid; \
		sleep .1; \
	done

.PHONY: run watch
