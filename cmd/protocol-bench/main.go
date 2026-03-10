package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"mpc-test/internal/mpc"
)

type row struct {
	Protocol            string
	Rounds              int
	Messages            int
	BytesPerOp          int
	SignAvgMS           float64
	VerifyAvgMS         float64
	CPUWorkAvgMS        float64
	NetworkEstimateMS   float64
	ThroughputPerSecond float64
}

func main() {
	iterations := flag.Int("n", 200, "每个协议执行次数")
	messageSize := flag.Int("msg-size", 256, "签名消息字节数")
	rttMS := flag.Float64("rtt-ms", 20, "估算单轮网络 RTT(ms)")
	bandwidthMbps := flag.Float64("bandwidth-mbps", 50, "估算链路带宽(Mbps)")
	csvPath := flag.String("csv", "", "可选：输出 CSV 文件路径")
	flag.Parse()

	if *iterations <= 0 || *messageSize <= 0 || *rttMS <= 0 || *bandwidthMbps <= 0 {
		fmt.Fprintln(os.Stderr, "invalid args: n/msg-size/rtt-ms/bandwidth-mbps must be > 0")
		os.Exit(2)
	}

	msg := []byte(strings.Repeat("a", *messageSize))
	rows := make([]row, 0, 5)

	for _, name := range mpc.AvailableProtocols() {
		p, err := mpc.NewByName(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "new protocol %s failed: %v\n", name, err)
			os.Exit(1)
		}

		var signTotal, verifyTotal time.Duration
		var rounds, messages, bytesPerOp int

		for i := 0; i < *iterations; i++ {
			s0 := time.Now()
			sig, _, err := p.SignTransfer(msg)
			signTotal += time.Since(s0)
			if err != nil {
				fmt.Fprintf(os.Stderr, "sign failed protocol=%s iter=%d: %v\n", name, i, err)
				os.Exit(1)
			}

			v0 := time.Now()
			ok, err := p.Verify(msg, sig)
			verifyTotal += time.Since(v0)
			if err != nil || !ok {
				fmt.Fprintf(os.Stderr, "verify failed protocol=%s iter=%d err=%v ok=%v\n", name, i, err, ok)
				os.Exit(1)
			}

			m := p.LastMetrics()
			rounds = m.Rounds
			messages = m.Messages
			bytesPerOp = m.BytesEstimate
		}

		signAvg := float64(signTotal.Microseconds()) / 1000 / float64(*iterations)
		verifyAvg := float64(verifyTotal.Microseconds()) / 1000 / float64(*iterations)
		cpuWork := signAvg + verifyAvg
		netMs := float64(rounds)*(*rttMS) + (float64(bytesPerOp*8) / (*bandwidthMbps * 1000 * 1000) * 1000)
		throughput := 1000 / (cpuWork + netMs)

		rows = append(rows, row{
			Protocol: name, Rounds: rounds, Messages: messages, BytesPerOp: bytesPerOp,
			SignAvgMS: signAvg, VerifyAvgMS: verifyAvg, CPUWorkAvgMS: cpuWork,
			NetworkEstimateMS: netMs, ThroughputPerSecond: throughput,
		})
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].NetworkEstimateMS < rows[j].NetworkEstimateMS })
	printMarkdownTable(rows, *iterations, *messageSize, *rttMS, *bandwidthMbps)
	if *csvPath != "" {
		if err := writeCSV(*csvPath, rows); err != nil {
			fmt.Fprintf(os.Stderr, "write csv failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nCSV saved: %s\n", *csvPath)
	}
}

func printMarkdownTable(rows []row, n, msgSize int, rttMS, bw float64) {
	fmt.Printf("# MPC Protocol Benchmark\n\n")
	fmt.Printf("- Iterations per protocol: **%d**\n", n)
	fmt.Printf("- Message size: **%d bytes**\n", msgSize)
	fmt.Printf("- Network model: RTT=**%.2f ms**, Bandwidth=**%.2f Mbps**\n\n", rttMS, bw)
	fmt.Println("| Protocol | Rounds | Messages | Bytes/Op | Sign Avg (ms) | Verify Avg (ms) | CPU Work Avg (ms) | Network Est. (ms) | End-to-End TPS |")
	fmt.Println("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
	for _, r := range rows {
		fmt.Printf("| %s | %d | %d | %d | %.3f | %.3f | %.3f | %.3f | %.3f |\n",
			r.Protocol, r.Rounds, r.Messages, r.BytesPerOp, r.SignAvgMS, r.VerifyAvgMS, r.CPUWorkAvgMS, r.NetworkEstimateMS, r.ThroughputPerSecond)
	}

	tw := tabwriter.NewWriter(os.Stdout, 2, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "\nHuman Summary:")
	for i, r := range rows {
		fmt.Fprintf(tw, "%d) %s\t网络估算 %.2fms\tCPU %.3fms\tTPS %.2f\n", i+1, r.Protocol, r.NetworkEstimateMS, r.CPUWorkAvgMS, r.ThroughputPerSecond)
	}
	_ = tw.Flush()
}

func writeCSV(path string, rows []row) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"protocol", "rounds", "messages", "bytes_per_op", "sign_avg_ms", "verify_avg_ms", "cpu_work_avg_ms", "network_estimate_ms", "end_to_end_tps"}); err != nil {
		return err
	}
	for _, r := range rows {
		rec := []string{
			r.Protocol,
			fmt.Sprintf("%d", r.Rounds),
			fmt.Sprintf("%d", r.Messages),
			fmt.Sprintf("%d", r.BytesPerOp),
			fmt.Sprintf("%.6f", r.SignAvgMS),
			fmt.Sprintf("%.6f", r.VerifyAvgMS),
			fmt.Sprintf("%.6f", r.CPUWorkAvgMS),
			fmt.Sprintf("%.6f", r.NetworkEstimateMS),
			fmt.Sprintf("%.6f", r.ThroughputPerSecond),
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	return nil
}
