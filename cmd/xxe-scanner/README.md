# XXE Scanner

This tool scans a given URL for XML External Entity (XXE) vulnerabilities.

## Building

To build the scanner, run the following command from the root of the repository:

```
go build -o xxe-scanner cmd/xxe-scanner/main.go
```

## Usage

To scan a URL, run the following command:

```
./xxe-scanner <url>
```

Replace `<url>` with the URL you want to scan. The tool will send a malicious XML payload to the URL and report whether the target is vulnerable to XXE.
