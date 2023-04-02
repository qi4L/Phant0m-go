package main

import (
	"GoLangPhant0m/Phant0m"
	"flag"
	"fmt"
	"os"
)

var (
	PID_1       bool
	PID_2       bool
	Technique_1 bool
	Technique_2 bool
)

func usage() {
	fmt.Println(`Usage of main.exe:
  -p1 PID_1
      从服务管理器中获取事件日志服务的PID
  -p2 PID_2
      从WMI中获取事件日志服务的PID
  -t1 Technique_1
      使用方法1
  -t2 Technique_2
      使用方法2
  `)
}

func main() {
	flag.BoolVar(&PID_1, "p1", false, "事件日志服务的PID从服务管理器中获取")
	flag.BoolVar(&PID_2, "p2", false, "从事件日志服务的PID从WMI中获取")
	flag.BoolVar(&Technique_1, "t1", false, "使用方法1")
	flag.BoolVar(&Technique_2, "t2", false, "使用方法2")
	flag.Usage = usage
	flag.Parse()
	if Technique_1 == false && Technique_2 == false {
		usage()
		os.Exit(0)
	}
	Phant0m := Phant0m.WorkExp{
		P1: PID_1,
		P2: PID_2,
		T1: Technique_1,
		T2: Technique_2,
	}
	Phant0m.Run()
}
