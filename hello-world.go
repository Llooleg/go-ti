package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/VirusTotal/vt-go"
	"github.com/joho/godotenv"
)

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
		fmt.Println("Could not find stats for this link.")
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
