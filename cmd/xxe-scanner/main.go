package main

import (
	"bug-bounty-toolkit/pkg/xxe"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: xxe-scanner <url>")
		os.Exit(1)
	}
	url := os.Args[1]

	fmt.Printf("Scanning %s for XXE vulnerabilities...\n", url)
	vulnerable, err := xxe.ScanURL(url)
	if err != nil {
		fmt.Printf("An error occurred: %s\n", err)
		os.Exit(1)
	}

	if vulnerable {
		fmt.Println("The target is vulnerable to XXE!")
	} else {
		fmt.Println("The target is not vulnerable to XXE.")
	}
}
