# Build

Run the build from the repository root after installing the dependencies listed in `INSTALL.md` or after entering the Vagrant VM.
`make libbpf-static` prepares the vendored libbpf archive, and `make build` compiles the eBPF objects and the safeguard binary.

```shell
$ vagrant ssh

$ cd /vagrant/safeguard
$ make libbpf-static
$ make build
```

# Test

```shell
$ make test
```
