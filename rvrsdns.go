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
	Threads    int    `short:"t" long:"threads" default:"8" description:"How many threads should be used"`
	ResolverIP string `short:"r" long:"resolver" description:"IP of the DNS resolver to use for lookups"`
	Protocol   string `short:"P" long:"protocol" choice:"tcp" choice:"udp" default:"udp" description:"Protocol to use for lookups"`
	Port       uint16 `short:"p" long:"port" default:"53" description:"DNS resolver port"`
	Domain     string `short:"d" long:"domain" description:"Filter results to include only domains containing this substring"`
	OutputFile string `short:"o" long:"output" default:"results.txt" description:"File to write output to"`
	CommonPorts []int `long:"common-ports" description:"Common ports to scan" default:"80,443,22,21"`
}

func main() {
	_, err := flags.ParseArgs(&opts, os.Args)
	if err != nil {
		os.Exit(1)
	}

	work := make(chan string)
	wg := &sync.WaitGroup{}
	results := make(chan string)

	// Start worker goroutines
	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go worker(work, results, wg)
	}

	// Collect results and write to file
	go writeResults(results)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		work <- scanner.Text()
	}
	close(work)
	wg.Wait()
	close(results)
}

func worker(work <-chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	var resolver *net.Resolver
	if opts.ResolverIP != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, opts.Protocol, fmt.Sprintf("%s:%d", opts.ResolverIP, opts.Port))
			},
		}
	}

	for cidr := range work {
		ips, err := expandCIDR(cidr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error expanding CIDR %s: %v\n", cidr, err)
			continue
		}
		for _, ip := range ips {
			addr, err := resolver.LookupAddr(context.Background(), ip)
			if err != nil {
				continue
			}
			for _, a := range addr {
				if strings.Contains(a, opts.Domain) {
					for _, port := range opts.CommonPorts {
						open, _ := scanPort(ip, port)
						if open {
							results <- fmt.Sprintf("%s:%d is open\n", ip, port)
						}
					}
				}
			}
		}
	}
}

func scanPort(ip string, port int) (bool, error) {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, 1*time.Second)
	if err != nil {
		return false, err
	}
	conn.Close()
	return true, nil
}

func writeResults(results <-chan string) {
	file, err := os.Create(opts.OutputFile)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	for result := range results {
		file.WriteString(result)
	}
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

	// Remove network address and broadcast address if applicable
	if len(ips) > 2 {
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
