Name: safeguard
Version: 3.0
Release: 3%{?dist}
Summary: A tool for restricting network, file, mount and process operations using eBPF
License: MIT
URL: https://atomgit.com/openeuler/safeguard
Source: %{name}-%{version}.tar.gz

BuildRequires: gcc, clang, llvm, elfutils-libelf-devel, zlib-devel, golang, bpftool
Requires: bpftool

%define debug_package %{nil}

%description
Safeguard is a tool for restricting network, file, mount and process operations using eBPF. It can be used to implement security policies for containers or processes.

%prep
%setup -q -n safeguard

%build
export GO111MODULE="on"
export GOPROXY="https://goproxy.cn,direct"
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
* Wed May 13 2026 Tongyx <tongyx12@chinaunicom.cn> - 3.0.3
- Fix process whitelist map value size and IPv4 CIDR trie key encoding
- Narrow generated network allow entries to host CIDRs and skip unspecified addresses
- Normalize and cap generated whitelist entries to match eBPF map limits

* Thu May 07 2026 Tongyx <tongyx12@chinaunicom.cn> - 3.0.2
- Fix network monitor mode event reporting
- Fix process config check and add enable field support
- Add process exec audit event reporting via ringbuf
- Add basename extraction for process whitelist matching

* Thu Apr 24 2026 Tongyx <tongyx12@chinaunicom.cn> - 3.0.1
- Add whitelist policy support
- Add controller generate command
- Add process whitelist blocking via LSM hook
- Enhance CLI help with usage examples

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
