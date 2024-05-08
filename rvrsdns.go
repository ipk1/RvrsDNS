
package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	flags "github.com/jessevdk/go-flags"
)

var opts struct {
	Threads     int    `short:"t" long:"threads" default:"8" description:"How many threads should be used"`
	ResolverIP  string `short:"r" long:"resolver" description:"IP of the DNS resolver to use for lookups"`
	Protocol    string `short:"P" long:"protocol" choice:"tcp" choice:"udp" default:"udp" description:"Protocol to use for lookups"`
	Port        uint16 `short:"p" long:"port" default:"53" description:"DNS resolver port"`
	Domain      string `short:"d" long:"domain" description:"Filter results to include only domains containing this substring"`
	InputFile   string `short:"i" long:"input" description:"Input file with CIDR blocks"`
	OutputFile  string `short:"o" long:"output" default:"results.txt" description:"File to write output to"`
	CommonPorts []int  `short:"c" long:"common-ports" description:"Common ports to scan" default:"80,443,22,21"`
}

func main() {
	_, err := flags.ParseArgs(&opts, os.Args)
	if err != nil {
		os.Exit(1)
	}

	work := make(chan string)
	results := make(chan string)
	wg := &sync.WaitGroup{}

	// Start workers
	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go worker(work, results, wg)
	}

	// Read CIDRs from file and send them to workers
	file, err := os.Open(opts.InputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open file: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		work <- scanner.Text()
	}
	close(work)

	wg.Wait()
	close(results)

	// Write results to file
	writeResults(results)
}

func worker(work chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	var resolver *net.Resolver
	if opts.ResolverIP != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.DialContext(ctx, opts.Protocol, fmt.Sprintf("%s:%d", opts.ResolverIP, opts.Port))
			},
		}
	}

	for cidr := range work {
		ips, _ := expandCIDR(cidr)
		for _, ip := range ips {
			checkAndReport(ip, results, resolver)
		}
	}
}

func checkAndReport(ip string, results chan<- string, resolver *net.Resolver) {
	live := false
	var livePorts []int
	for _, port := range opts.CommonPorts {
		if open, _ := scanPort(ip, port); open {
			live = true
			livePorts = append(livePorts, port)
		}
	}

	if !live {
		return
	}

	addr, err := resolver.LookupAddr(context.Background(), ip)
	if err != nil || len(addr) == 0 {
		results <- fmt.Sprintf("%s is live but no hostnames found", ip)
		return
	}

	for _, a := range addr {
		domain := strings.TrimRight(a, ".")
		if opts.Domain == "" || strings.Contains(domain, opts.Domain) {
			for _, port := range livePorts {
				results <- fmt.Sprintf("%s:%d - %s is live", ip, port, domain)
			}
		}
	}
}

func scanPort(ip string, port int) (bool, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), 1*time.Second)
	if conn != nil {
		conn.Close()
	}
	return err == nil, nil
}

func writeResults(results <-chan string) {
	file, err := os.Create(opts.OutputFile)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for result := range results {
		writer.WriteString(result + "\n")
	}
	writer.Flush()
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 1 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}
