// main.go
package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
)

func main() {
	// 1. 加载 eBPF 程序
	objs := tcxdpObjects{}
	if err := loadTcxdpObjects(&objs, nil); err != nil {
		log.Fatalf("加载 eBPF 对象失败: %v", err)
	}
	defer objs.Close()

	// 2. 获取网络接口（例如 eth0）
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		log.Fatalf("获取网络接口失败: %v", err)
	}

	// 3. 挂载 XDP 程序到接口
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpTrafficMonitor,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // 或 link.XDPDriverMode（如果驱动支持）
	})
	if err != nil {
		log.Fatalf("挂载 XDP 失败: %v", err)
	}
	defer xdpLink.Close()

	// 4. 定期读取统计数据
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var key uint16 = 8080
	for range ticker.C {
		var stats tcxdpTrafficStats

		// 从 Map 中读取数据
		if err := objs.StatsMap.Lookup(key, &stats); err != nil {
			log.Printf("读取 stats_map 失败: %v", err)
			continue
		}

		fmt.Printf("[%s] 端口 %d 入口流量统计:\n", time.Now().Format(time.RFC3339), key)
		fmt.Printf("  RX: %d 字节, %d 数据包\n", stats.RxBytes, stats.RxPackets)
	}
}
