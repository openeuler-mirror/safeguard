# Build

Run the build from the repository root after installing the dependencies listed in `INSTALL.md` or after entering the Vagrant VM.
`make libbpf-static` prepares the vendored libbpf archive, and `make build` compiles the eBPF objects and the safeguard binary.

```shell
$ vagrant ssh

$ cd /vagrant/safeguard
$ make libbpf-static
$ make build
```

## Build Targets

The `Makefile` provides the following targets:

| Target | Description |
|--------|-------------|
| `libbpf-static` | Build the vendored libbpf as a static archive (`output/libbpf.a`) |
| `build` | Compile eBPF objects and the Go binary |
| `test` | Run all Go tests (excluding audit packages that require CGO) |
| `test-cgo` | Run all tests including audit packages with CGO flags |
| `clean` | Remove build artifacts and the output directory |
| `install` | Install the safeguard binary to `/usr/local/bin` |

## Cross-Compilation

To build for a specific architecture, set the `GOARCH` environment variable:

```shell
$ GOARCH=amd64 make build
$ GOARCH=arm64 make build
```

## Build Output

After a successful build, the following files are placed in the `output/` directory:

- `safeguard` — The main binary
- `*.bpf.o` — Compiled eBPF object files
- `libbpf.a` — Static libbpf archive

## Build Dependencies

The build requires the following tools and libraries:

- Go >= 1.21
- clang/llvm (for compiling BPF programs)
- libelf-dev and zlib1g-dev
- bpftool (for generating BPF skeletons)
- make and gcc

See `INSTALL.md` for detailed installation instructions for each distribution.

# Test

```shell
$ make test
```

For audit package tests that require CGO:

```shell
$ CGO_CFLAGS="-I$(pwd)/output" CGO_LDFLAGS="-lelf -lz $(pwd)/output/libbpf.a" go test ./pkg/audit/...
```
