![](https://socialify.git.ci/nu1r/GoLangPhant0m/image?font=Raleway&forks=1&issues=1&language=1&logo=https%3A%2F%2Fs1.ax1x.com%2F2022%2F09%2F12%2FvXqOUI.jpg&name=1&owner=1&pattern=Signal&pulls=1&stargazers=1&theme=Light)
[Phant0m项目重构](https://github.com/hlldz/Phant0m)

Svchost 在所谓的共享服务进程的实现中是必不可少的，其中多个服务可以共享一个进程以减少资源消耗。将多个服务分组到一个进程中可以节省计算资源，NT 设计者特别关注这一考虑，因为创建 Windows 进程比在其他操作系统（例如 Unix 系列）中花费更多的时间和消耗更多的内存。<sup>[1](https://en.wikipedia.org/wiki/Svchost.exe)</sup>

简而言之，这意味着；在 Windows 操作系统上，svchost.exe 管理服务，服务实际上作为线程在 svchost.exe 下运行。Phant0m 以事件日志服务为目标，找到负责事件日志服务的进程，检测并杀死负责事件日志服务的线程。因此，虽然事件日志服务似乎在系统中运行（因为 Phant0m 没有终止进程），但它实际上并没有运行（因为 Phant0m 终止了线程）并且系统不收集日志。

# 检测事件日志服务

获取事件日志服务有两个方法
1. 通过 SCM（服务控制管理器）检测
2. 通过 WMI（Windows 管理规范）检测（待写）

# 杀死线程

## 方法一

当每项服务在运行 Windows Vista 或更高版本的计算机上注册时，服务控制管理器 (SCM) 会为该服务分配一个唯一的数字标记（按升序排列）。然后，在服务创建时，标签被分配给主服务线程的 TEB。然后，此标记将传播到主服务线程创建的每个线程。例如，如果 Foo 服务线程创建了一个 RPC 工作线程（注意：RPC 工作线程稍后不会更多地使用线程池机制），该线程将具有 Foo 服务的服务标签。2个

因此，在此技术中，Phant0m 将使用 NtQueryInformationThread API 检测事件日志服务的线程，以获取线程的 TEB 地址并从 TEB 中读取 SubProcessTag。然后它会终止与事件日志服务相关的线程。

## 方法二

在这种技术中，Phant0m 检测与线程关联的 DLL 的名称。Windows 事件日志服务使用wevtsvc.dll. 完整路径是%WinDir%\System32\wevtsvc.dll. 如果线程正在使用该 DLL，则它是 Windows 事件日志服务的线程，然后 Phant0m 会终止该线程。

# 用法

```text
-p1 PID_1
      从服务管理器中获取事件日志服务的PID
  -p2 PID_2
      从WMI中获取事件日志服务的PID
  -t1 Technique_1
      使用方法1
  -t2 Technique_2
      使用方法2
```

# 示例

```plan9_x86
go run main.go -p1 -t1 1
```