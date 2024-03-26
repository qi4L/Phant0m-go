Svchost is essential in the implementation of so-called shared service processes, where multiple services can share a process to reduce resource consumption. Grouping multiple services into a single process saves computing resources, a consideration that was of particular concern to NT designers because creating Windows processes takes more time and consumes more memory than in other operating systems, such as the Unix family. <sup>[1](https://en.wikipedia.org/wiki/Svchost.exe)</sup>

In a nutshell, this means; on Windows operating systems, svchost.exe manages the service, and the service actually runs as a thread under svchost.exe. Phant0m targets the event log service, finds the process responsible for the event log service, detects and kills the thread responsible for the event log service. Therefore, although the event log service appears to be running on the system (because Phant0m did not terminate the process), it is not actually running (because Phant0m terminated the thread) and the system does not collect logs.

# Detect event log service

There are two methods to obtain the event log service
1. Detect via SCM (Service Control Manager)
2. Detection via WMI (Windows Management Instrumentation) (to be written)

# Kill thread

## method one

When each service is registered on a computer running Windows Vista or later, the Service Control Manager (SCM) assigns the service a unique numerical tag (in ascending order). Then, at service creation time, the label is assigned to the TEB of the main service thread. This tag will then be propagated to every thread created by the main service thread. For example, if the Foo service thread creates an RPC worker thread (note: RPC worker threads will not make more use of the thread pool mechanism later), that thread will have the service label of the Foo service. 2

So, in this technique, Phant0m will detect the event log service's thread using the NtQueryInformationThread API to get the thread's TEB address and read the SubProcessTag from the TEB. It then terminates the thread related to the event log service.

## Method Two

In this technique, Phant0m detects the name of the DLL associated with the thread. The Windows Event Log Service uses wevtsvc.dll. The full path is %WinDir%\System32\wevtsvc.dll. If a thread is using that DLL, then it is a Windows Event Log Service thread, and then Phant0m terminates that thread.

# Usage

```text
-p1 PID_1
       Get the PID of the event log service from the service manager
   -p2 PID_2
       Get the PID of the event log service from WMI
   -t1 Technique_1
       How to use 1
   -t2 Technique_2
       How to use 2
```

# Example

```plan9_x86
go run main.go -p1 -t1 1
```
