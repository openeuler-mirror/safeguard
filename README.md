# safeguard: Linux security audit, control, and behavior analysis tools based on KRSI(eBPF+LSM)

针对操作系统、内核安全，safeguard是一个基于eBPF的Linux审计观测工具，可以实现安全操作的拦截及审计记录。项目采用libbpfgo库，使用go语言实现顶层控制

# 特性

* 审计：日志记录配置范围内的行为
* 控制：针对文件，进程，网络的安全访问控制
* 行为分析：收集信息，进行资源，热点，异常等分析
* 主机管理：从安全角度自动化构建细粒度资产信息
* 风险管理：精准发现内部风险，快速定位问题并有效解决安全风险
* 入侵检测：提供多锚点的检测能力，能够实时、准确的感知入侵事件，发现失陷主机，并提供对入侵事件的响应手段。


![architecture](docs/architecture.png)

# 编译
内核配置参考 https://gitee.com/openeuler/safeguard/blob/master/INSTALL.md

```shell
$ git clone --recursive https://gitee.com/openeuler/safeguard.git && cd safeguard
# $ vagrant up && vagrant reload
# $ vagrant ssh

$ make build

$ sudo ./build/safeguard --config config/safeguard.yml
```

# 安装
```shell
$ wget https://gitee.com/openeuler/safeguard/releases/download/v2.0.1/safeguard-2.0.1-2.ule3.x86_64.rpm
$ yum install safeguard-2.0.1-2.ule3.x86_64.rpm
$ sudo safeguard --config /etc/safeguard/safeguard.yml
```

# configurate map
```shell
$ bpftool map update pinned /sys/fs/bpf/file_config key 00 00 00 00 value 01 00 00 00 00 00 00 00
```

# 项目功能(部分位于开发阶段)

### 审计控制
文件：
- 追踪文件系统的活动，包括文件的打开、关闭、读写、删除等。
- 修改文件系统的行为，例如拦截某些文件操作，或者实现自定义的**安全策略**。
	安全策略：
    1.  拦截或重定向某些文件操作，使用eBPF来拦截对敏感文件的读写操作，或者重定向对某些文件的访问到其他位置。
    2.  实现自定义的访问控制，使用eBPF来检查对文件的访问者的身份、权限、环境等信息，然后根据一些规则来允许或拒绝访问。
    3.  实现自定义的审计和监控，使用eBPF来记录对某些文件的操作的详细信息，如操作者、时间、内容等，并将这些信息输出到日志。

进程：
- 追踪进程的生命周期，例如进程的创建、终止、调度、上下文切换等。
- 修改进程的行为，例如注入或修改某些系统调用，或者实现自定义的调度策略。

网络：
- 追踪网络的活动，例如网络包的发送、接收、转发、丢弃等。
- 修改网络的行为，例如过滤或重写某些网络包，或者实现自定义的路由策略。


### 行为分析
- 收集并分析文件系统的性能、热点、异常等。（选择合适的eBPF程序类型和挂载点，例如，使用kprobes或tracepoints来追踪文件系统相关的内核函数或事件，如vfs\_read, vfs\_write, ext4\_sync\_file等。）
    
- 收集信息来分析进程的资源消耗、状态变化、依赖关系等（do\_fork, do\_exit, schedule等）。
- 收集信息，分析网络的流量、延迟、丢包率、拥塞等（使用tc或xdp来追踪网络包的发送、接收、转发、丢弃等事件）。

### 主机管理
从安全角度自动化构建细粒度资产信息，支持对业务层资产精准识别和动态感知，让保护对象清晰可见。
- 账号展示
- 端口列表
- 进程列表

### 风险管理
精准发现内部风险，快速定位问题并有效解决安全风险，提供详细的资产信息、风险信息以供分析和响应。
- 漏洞检测
- 安全补丁
- 弱密码
- 系统风险
- 账号风险

### 入侵检测
提供多锚点的检测能力，能够实时、准确的感知入侵事件，发现失陷主机，并提供对入侵事件的响应手段。
- 暴力破解
- 异常登录
- 反弹shell
- 本地提权
- 后门检测，Web后门


# 开发路线

|           |                                     | 22.03 LTS SPx| 24.03 LTS | 24.03 SPx | 已实现 |
|-|-|:-:|:-:|:-:|:-:|
| 控制-主机规则设置 | 文件操作拦截                     |              |           |           | ✓    |
|                | 进程拦截（采用path hook）         | ✓            |           |           |  ✓   |
|                | 网络拦截                         |              |           |           |  ✓   |
| 主机管理      | 账号                              | ✓             |           |           |     |
|              | 端口                              | ✓             |           |           |     |
|              | 进程                              | ✓             |           |           |     |
| 风险管理      | 漏洞检测                           |               |           | ✓         |     |
|              | 安全补丁                          |                |           | ✓         |     |
|              | 弱密码                            |                |           | ✓         |     |
|              | 系统风险                          |                |           | ✓         |     |
|              | 账号风险                          |                |           | ✓         |     |
| 入侵检测      | 暴力破解                          |                | ✓         |           |     |
|             | 异常登录                           |                | ✓         |           |     |
|             | 反弹shell                         |                |           | ✓         |      |
|             | 本地提权                           |                | ✓         |           |      |
|             | 后门检测，Web后门                    |               |           | ✓         |      |
| 安全日志     | 审计日志：文件hook拦截方式由路径更改为inode | ✓          |           |           |  ✓   |
|             | 登录日志                           | ✓              |           |           |      |
|             | 账户变更日志                        |                | ✓         |           |      |
| 三权分立     | 三权分立                            |                |           |           |      |

# LICENSE

safeguard's userspace program is licensed under Apache License 2.0 License.  
eBPF programs inside [pkg/bpf directory](pkg/bpf) are licensed under [GNU General Public License version 2](./pkg/bpf/LICENSE.md).  
