EXECUTABLE=executable-name
WINDOWS=$(EXECUTABLE)_windows_amd64.exe
LINUX=$(EXECUTABLE)_linux_amd64
DARWIN=$(EXECUTABLE)_darwin_amd64
filename=

windows: $(WINDOW'S) ## Build for Windows

linux: $(LINUX) ## Build for Linux

darwin: $(DARWIN) ## Build for Darwin (macOS)

$(WINDOWS):
	env GOOS=windows GOARCH=amd64 go build -i -v -o $(WINDOWS) $(filename)
	env GOOS=windows GOARCH=i386 go build -i -v -o $(WINDOWS) $(filename)

$(LINUX):
	env GOOS=linux GOARCH=amd64 go build -i -v -o $(LINUX) $(filename)
	env GOOS=linux GOARCH=i386 go build -i -v -o $(LINUX) $(filename)

$(DARWIN):
	env GOOS=darwin GOARCH=amd64 go build -i -v -o $(DARWIN) $(filename)
	env GOOS=darwin GOARCH=i386 go build -i -v -o $(DARWIN) $(filename)

all: test build ## Build and run tests

cross-compile:
	env GOOS=darwin GOARCH=amd64 go build -i -v -o $(DARWIN) $(filename)
	env GOOS=linux GOARCH=amd64 go build -i -v -o $(LINUX) $(filename)
	#env GOOS=linux GOARCH=386 go build -i -v -o $(LINUX) $(filename)
	env GOOS=windows GOARCH=amd64 go build -i -v -o $(WINDOWS) $(filename)
	#env GOOS=windows GOARCH=386 go build -i -v -o $(WINDOWS) $(filename)

clean: ## Remove previous build
	rm -f $(WINDOWS) $(LINUX) $(DARWIN)

.PHONY: all test clean

help: ## Display available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'





























