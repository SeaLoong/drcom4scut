# drcom4scut

> 当前版本  0.2.4

+ A 3rd-party DrCOM client for SCUT, written in Rust.
+ 华南理工大学第三方客户端，使用Rust语言编写。

------------------------------------------------------

## 用法

> 仅供不熟悉操作的同学参考，熟悉的话直接看命令行参数和配置项应该就知道怎么用了

1. 下载 Release 并解压。
2. 运行 run.bat，第一次会产生配置文件。
   + 你也可以直接在 drcom4scut.exe 后面加参数来运行，详情请用 -h 参数获取帮助。
3. 填写配置文件，通常只需要填写 `username` 和 `password` 两项（注意yml文件格式）。
4. 再次运行 run.bat，通常是可以正常运行的。
   + 如果不能，请查看控制台输出的提示。
     + 如果没有自动选择正确的网卡，请在配置文件或控制台参数中填写 `mac` 或 `ip` 任意一项。其中 `mac` 是以冒号分隔的形式， `ip` 是你指定网卡对应设置的IP地址。
     + 如果出现不能读取配置文件，请检查填写的配置文件是否满足yml规范。

------------------------------------------------------

## 命令行参数

```bash
USAGE:
    drcom4scut.exe [FLAGS] [OPTIONS]

FLAGS:
        --debug      Enable debug mode.
    -h, --help       Prints help information
        --nolog      !!!注意：如果构建时启用了nolog特性则不会有这项!!! Disable logger, no any output at all, unless PANIC or EXCEPTION of program occurred.
        --noudp      Disable UDP Process.
    -V, --version    Prints version information

OPTIONS:
    -c, --config <config>        (Optional) Path to config file. Some settings only can be set by config file.
    -d, --dns <dns>              (Optional) DNS server. If more than one, you can add the remain DNS servers to config
                                 file.
    -H, --host <host>            (Optional) Host to connect UDP server. Default value is 's.scut.edu.cn'.
    -N, --hostname <hostname>    (Optional) Default value is current computer host name.
    -i, --ip <ip>                (Optional) IP address of the selected Ethernet Device.
    -m, --mac <mac>              (Optional) Ethernet Device MAC address.
    -p, --password <password>    Password to authorize.
    -t, --time <time>            (Optional) Time to reconnect automatically after you are not allowed to access
                                 Internet. Default value is 7:00.
    -u, --username <username>    Username to authorize.
```

------------------------------------------------------

## 配置项

```yml
mac:   # (可选)网卡MAC地址，以冒号':'分隔
ip:   # (可选)网卡对应设置的IP地址
username: ''  # 账号（学号）
password: ''  # 密码
dns:   # 学校DNS服务器IP地址，默认已填入五山校区和大学城校区的DNS
  - 202.38.193.33
  - 222.201.130.30
  - 202.112.17.33
  - 222.201.130.33
host: s.scut.edu.cn   # (可选) 用于UDP连接的地址，通常不需要改动
hostname:   # (可选) 主机名，留空会使用当前电脑的主机名
time: 7:00   # (可选) 在收到“本时段禁止上网”后的重连时间，默认为7点整
reconnect: 15   # (可选) 出现意外情况时的重连间隔，默认为15秒
heartbeat:
  eap_timeout: 60   # (可选) EAP连接心跳间隔，默认为60秒
  udp_timeout: 12   # (可选) UDP连接心跳间隔，默认为12秒
retry:
  count: 2   # (可选) 错误重试次数
  interval: 5000   # (可选) 数据包重发间隔、错误重试间隔，默认为5000毫秒
log:
  enable_console: false   # (可选) 是否输出日志到控制台
  enable_file: false   # (可选) 是否输出日志到文件
  file_directory: ./logs   # (可选) 日志文件目录
  level: INFO   # (可选) 日志等级
data:   # (可选) 以下参数通常不需要填写，填写错误可能会导致不可预计的问题
  response_identity:
    unknown:
  response_md5_challenge:
    unknown:
  misc_info:
    unknown1:
    cks32_param:
    unknown2:
    os_major:
    os_minor:
    os_build:
    os_unknown:
    version:
    hash:
```

------------------------------------------------------

## 构建和编译

### 一般构建

```bash
cargo build --release
```

+ 如果你想去掉程序的日志(log)功能，可以启用 `nolog` 特性

    ```bash
    cargo build --release --features nolog
    ```

+ 需要使用 *Nightly* 版本的 Rust 进行编译。

+ 由于使用了 [**libpnet**](https://crates.io/crates/pnet) ，在Windows下需要安装 *WinPcap* 或 *pcap* 才能进行编译，详见[**libpnet**](https://crates.io/crates/pnet)。

+ 目前在 Windows/Ubuntu(感谢hyh) 下编译通过，其余环境暂未测试。

### OpenWRT

+ 由于并没有了解这方面，待补充。

------------------------------------------------------

## 许可证

[![LGPLv3](https://img.shields.io/badge/License-LGPLv3-blue.svg?longCache=true)](https://github.com/SeaLoong/drcom4scut/blob/master/LICENSE)

------------------------------------------------------

## 鸣谢

+ hyh
+ cq
+ 所有参与使用的同学
