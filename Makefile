SHELL := /bin/bash -o pipefail
KERNEL_ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BPF_BUILDDIR := pkg/bpf/bytecode
BASEDIR = $(abspath .)
OUTPUT = output
INCLUDES := -I$(BASEDIR)/$(OUTPUT)
LIBBPF_SRC = $(abspath libbpf/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)
LIBBPF_OBJDIR = $(abspath ./$(OUTPUT)/libbpf)
LIBBPF_DESTDIR = $(abspath ./$(OUTPUT))
LLVM_STRIP ?= $(shell which llvm-strip || which llvm-strip-12)
CLANG_BPF_SYS_INCLUDES := `shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }'`
CGOFLAG = CGO_CFLAGS="-I$(BASEDIR)/$(OUTPUT)" CGO_LDFLAGS="-lelf -lz $(LIBBPF_OBJ)"
STATIC=-extldflags -static

.PHONY: libbpf-static
libbpf-static: $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch])
	CC="gcc" CFLAGS="-g -O2 -Wall -fpie" \
	   $(MAKE) -C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OBJDIR) \
		DESTDIR=$(LIBBPF_DESTDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install
	$(eval STATIC=-extldflags -static)

.PHONY: libbpf
libbpf: $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch])
	CC="gcc" CFLAGS="-g -O2 -Wall -fpie" \
	   $(MAKE) -C $(LIBBPF_SRC) \
		OBJDIR=$(LIBBPF_OBJDIR) \
		DESTDIR=$(LIBBPF_DESTDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

$(BPF_BUILDDIR):
	mkdir -p $(BPF_BUILDDIR)
	mkdir -p build

$(BPF_BUILDDIR)/%.bpf.o: pkg/bpf/c/%.bpf.c $(wildcard bpf/*.h) | $(BPF_BUILDDIR)
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(KERNEL_ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -E $(filter %.c,$^) -o "$@.i"
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(KERNEL_ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

.PHONY: bpf-restricted-network
bpf-restricted-network: $(BPF_BUILDDIR)/restricted-network.bpf.o

.PHONY: bpf-restricted-file
bpf-restricted-file: $(BPF_BUILDDIR)/restricted-file.bpf.o

.PHONY: bpf-restricted-mount
bpf-restricted-mount: $(BPF_BUILDDIR)/restricted-mount.bpf.o

.PHONY: bpf-restricted-process
bpf-restricted-process: $(BPF_BUILDDIR)/restricted-process.bpf.o

tools: libbpf
	gcc -I$(OUTPUT) -L$(OUTPUT) -lbpf tools/load_bpf.c -o tools/load_bpf

.PHONY: build
build:  libbpf vmlinux bpf-restricted-network bpf-restricted-file bpf-restricted-mount bpf-restricted-process
	$(CGOFLAG) go build -tags netgo -ldflags "-w -s" -o build/safeguard cmd/safeguard/safeguard.go

build-static:  libbpf vmlinux bpf-restricted-network bpf-restricted-file bpf-restricted-mount bpf-restricted-process
	$(CGOFLAG) go build -tags netgo -ldflags "-w -s $(STATIC)" -o build/safeguard cmd/safeguard/safeguard.go

.PHONY: vmlinux
vmlinux:
	$(shell bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(OUTPUT)/vmlinux.h)

clean:
	rm -rf pkg/bpf/bytecode/*
	rm -rf output build tools/load_bpf

.PHONY: build/docker
build/docker:
	sudo docker build -t safeguard:latest .

.PHONY: test/unit
test/unit: bpf-restricted-network bpf-restricted-file bpf-restricted-mount bpf-restricted-process
	which gotestsum || go install gotest.tools/gotestsum@latest
	$(CGOFLAG) sudo -E `go env GOPATH`/bin/gotestsum -- --mod=vendor -bench=^$$ -race ./...

.PHONY: test
test: bpf-restricted-network bpf-restricted-file bpf-restricted-mount bpf-restricted-process
	which gotestsum || go install gotest.tools/gotestsum@latest
	$(CGOFLAG) sudo -E `go env GOPATH`/bin/gotestsum -- --tags=integration --mod=vendor -bench=^$$ -race ./...

.PHONY: test/integration/specify
test/integration/specify: bpf-restricted-network bpf-restricted-file bpf-restricted-mount bpf-restricted-process
	which gotestsum || go install gotest.tools/gotestsum@latest
	$(CGOFLAG) sudo -E go test -tags integration -run ${NAME} ./...

.PHONY: release/local
release/local: build build/docker
	CGO_CFLAGS="-I$(abspath $(OUTPUT))" CGO_LDFLAGS="-lelf -lz $(LIBBPF_OBJ)" goreleaser release --snapshot --rm-dist

.PHONY: release
release: build build/docker
	CGO_CFLAGS="-I$(abspath $(OUTPUT))" CGO_LDFLAGS="-lelf -lz $(LIBBPF_OBJ)" goreleaser release --rm-dist
	sudo docker push safeguard:latest
