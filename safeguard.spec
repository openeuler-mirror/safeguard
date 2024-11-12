Name: safeguard
Version: 2.0
Release: 2%{?dist}
Summary: A tool for restricting network, file, mount and process operations using eBPF
License: MIT
URL: https://gitee.com/openeuler/safeguard
Source0: %{name}-%{version}.tar.gz
Source1: https://gitee.com/openeuler/safeguard/archive/refs/tags/v%{version}.tar.gz

BuildRequires: gcc, clang, llvm, elfutils-libelf-devel, zlib-devel
Requires: bpftool

%define debug_package %{nil}

%description
Safeguard is a tool for restricting network, file, mount and process operations using eBPF. It can be used to implement security policies for containers or processes.

%prep
%setup -q -n safeguard

%build
export GOPROXY="https://goproxy.cn,direct"
go mod tidy
make build

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
* Tue Nov 12 2024 yuelg <yuelg@chinaunicom.cn> - 2.0.2
- adapt to kernel 6.x
- support move_mount
- fix sb_mount

* Fri Oct 11 2024 yuelg <yuelg@chinaunicom.cn> - 2.0.1
- adapt to kernel oe sp4
- support move_mount
- fix sb_mount

* Mon Jan 08 2024 Tongyx <tongyx12@chinaunicom.cn> - 2.0.0
- adaptation to kernel 5.10

* Wed Aug 09 2023 Tongyx <tongyx12@chinaunicom.cn> - 1.0.0
- Initial package
