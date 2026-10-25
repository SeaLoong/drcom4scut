---
layout: home
hero:
  name: drcom4scut
  text: 校园网连接，<br>简单一点。
  tagline: 为华南理工大学校园网准备的开源客户端。电脑上点击连接，路由器上持续运行，让断线恢复和日常认证更省心。
  image:
    src: /connection.svg
    alt: 电脑与校园网络保持连接的示意图
  actions:
    - theme: brand
      text: 下载
      link: https://github.com/SeaLoong/drcom4scut/releases/latest
    - theme: alt
      text: 第一次使用
      link: /desktop
features:
  - title: 电脑上，点一下连接
    details: Windows、Mac、Linux 图形界面，选择网卡、填写账号密码，就可以开始。支持记住账号和登录系统后自动连接。
    link: /desktop
    linkText: 使用图形界面
  - title: 路由器上，持续在线
    details: 为多种 OpenWrt 设备提供程序包，支持开机运行。搭配 LuCI 页面，在浏览器里查看状态、连接和断开。
    link: /guide/openwrt
    linkText: 安装到 OpenWrt
  - title: 用终端，自由安排
    details: 轻量认证核心，提供状态查询、日志和后台服务。保留默认设置即可开始，也能按自己的需要配置。
    link: /guide/getting-started
    linkText: 命令行快速开始
---

<div class="home-body">
  <h2>从下载到连接，三步开始</h2>
  <p class="home-lead">第一次使用推荐图形界面，跟着提示完成设置。</p>
  <div class="steps">
    <section><span class="step-number">1</span><h3>选好你的版本</h3><p>按电脑系统和处理器下载一体包，解压后打开图形界面即可。</p></section>
    <section><span class="step-number">2</span><h3>填写校园网账号</h3><p>接好网线，选择实际连接的网卡，填好账号密码，运行一次环境自检。</p></section>
    <section><span class="step-number">3</span><h3>点击连接</h3><p>等待窗口显示在线。保留客户端运行，它会在断线后自动尝试恢复。</p></section>
  </div>
  <ScreenshotPreview />
  <div class="help-panel"><div><h3>已经安装，想更新版本？</h3><p>在窗口中检查图形界面或核心的最新正式版，确认后自动下载安装，继续使用原来的账号和设置。</p></div><a href="./gui/update">查看更新方法 →</a></div>
  <div class="help-panel"><div><h3>使用校园 Wi-Fi？</h3><p>先连接 Wi-Fi，再通过学校网页登录。了解兼容页面的自动登录方式、入口设置和常见问题。</p></div><a href="./guide/portal">查看校园网页登录帮助 →</a></div>
</div>
