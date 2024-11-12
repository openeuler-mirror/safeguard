Name: safeguard
Version: 2.0.1
Release: 2%{?dist}
Summary: A tool for restricting network, file, mount and process operations using eBPF
License: MIT
URL: https://gitee.com/openeuler/safeguard
Source0: %{name}-v%{version}.tar.gz
Source1: https://gitee.com/openeuler/safeguard/archive/refs/tags/v%{version}.tar.gz

BuildRequires: gcc, clang, llvm, elfutils-libelf-devel, zlib-devel
Requires: bpftool

%define debug_package %{nil}

%description
Safeguard is a tool for restricting network, file, mount and process operations using eBPF. It can be used to implement security policies for containers or processes.

%prep
%setup -q -n safeguard-v%{version}

%build
go mod tidy
make libbpf-static && make build

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/safeguard
cp -a build/safeguard %{buildroot}/usr/bin/
cp -a config/safeguard.yml %{buildroot}/etc/safeguard/

%check
#make test/unit

%files
%license LICENSE
%doc README.md
/usr/bin/safeguard
/etc/safeguard/safeguard.yml

%changelog
* Mon Jan 08 2024 Tongyx <tongyx12@chinaunicom.cn> - 2.0.0
- adaptation to kernel 5.10

* Wed Aug 09 2023 Tongyx <tongyx12@chinaunicom.cn> - 1.0.0
- Initial package