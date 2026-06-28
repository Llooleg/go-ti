package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/VirusTotal/vt-go"
	"github.com/joho/godotenv"
)

type AbuseIPDBResponse struct {
	Data struct {
		IPAddress            string   `json:"ipAddress"`
		IsPublic             bool     `json:"isPublic"`
		IPVersion            int      `json:"ipVersion"`
		IsWhitelisted        bool     `json:"isWhitelisted"`
		AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
		CountryCode          string   `json:"countryCode"`
		UsageType            string   `json:"usageType"`
		ISP                  string   `json:"isp"`
		Domain               string   `json:"domain"`
		Hostnames            []string `json:"hostnames"`
		TotalReports         int      `json:"totalReports"`
		NumDistinctUsers     int      `json:"numDistinctUsers"`
		LastReportedAt       string   `json:"lastReportedAt"`
	} `json:"data"`
}

func isLink(str string) bool {
	u, err := url.ParseRequestURI(str)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func getSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to compute SHA256: %v", err)
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
func getIPAbuseReport(inputURL string) string {
	apiKey := os.Getenv("IPABUSEKEY")
	if apiKey == "" {
		log.Fatal("IPABUSEKEY is not set in the environment variables.")
	}
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		log.Fatal(err)
	}
	strippedURL := parsedURL.Hostname()
	ips, err := net.LookupIP(strippedURL)
	if err != nil {
		log.Fatalf("Failed to resolve domain: %v", err)
	}
	strippedURL = strings.TrimSpace(strippedURL)
	// 2. Filter for the first valid IPv4 (A record) address
	var ipAddress string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			fmt.Printf("First A Record: %s\n", ipv4.String())
			ipAddress = ipv4.String()
			break
		}
	}

	if ipAddress == "" {
		log.Fatalf("No A record (IPv4) found for host: %s", strippedURL)
	}

	apiPath := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s", ipAddress)
	req, err := http.NewRequest("GET", apiPath, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to retrieve abuse report: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("AbuseIPDB API returned non-OK status: %s (body: %s)", resp.Status, string(body))
	}

	status := fmt.Sprintf("Status: %s\n", resp.Status)
	bodyStr := fmt.Sprintf("Body: %s\n", string(body))
	return fmt.Sprintf("%s%s", status, bodyStr)
}

func linkAnalysis(client *vt.Client, link string) {
	encodedURL := base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(link)))
	apiPath := fmt.Sprintf("https://www.virustotal.com/api/v3/urls/%s", encodedURL)

	vtURL, err := url.Parse(apiPath)
	if err != nil {
		log.Fatalf("Invalid URL path: %v", err)
	}

	obj, err := client.GetObject(vtURL)
	if err != nil {
		log.Fatalf("Failed to retrieve report: %v", err)
	}

	stats, err := obj.Get("last_analysis_stats")
	if err != nil {
		fmt.Println("Could not find stats for this link.")
	} else {
		fmt.Printf("Analysis Stats: %v\n", stats)
	}
	ipabuseReportURL := getIPAbuseReport(link)
	if ipabuseReportURL != "" {
		report := getIPAbuseReport(ipabuseReportURL)
		fmt.Print(report)
	} else {
		fmt.Println("No IP address found for the provided link.")
	}

}

func fileAnalysis(client *vt.Client, filePath string) {
	sha256, err := getSHA256(filePath)
	if err != nil {
		log.Fatalf("Failed to compute SHA256: %v", err)
	}
	//fmt.Printf("File SHA256: %s\n", sha256)
	apiPath := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", sha256)

	vtURL, err := url.Parse(apiPath)
	if err != nil {
		log.Fatalf("Invalid URL path: %v", err)
	}
	obj, err := client.GetObject(vtURL)
	if err != nil {
		log.Fatalf("Failed to retrieve report: %v", err)
	}
	stats, err := obj.Get("last_analysis_stats")
	if err != nil {
		fmt.Println("Could not find stats for this file.")
	} else {
		fmt.Printf("Analysis Stats: %v\n", stats)
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
	APIKey := os.Getenv("VTKEY")
	if APIKey == "" {
		log.Fatal("VTKEY is not set in the environment variables.")
	}
	client := vt.NewClient(APIKey)
	fmt.Print("Enter a link or file path here: ")
	var input string
	fmt.Scanln(&input)

	if isLink(input) {
		linkAnalysis(client, input)
	} else {
		fileAnalysis(client, input)
	}

}
