package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/VirusTotal/vt-go"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err) // %v покажет реальную причину
	}
	APIKey := os.Getenv("VTKEY")
	if APIKey == "" {
		log.Fatal("VTKEY is not set in the environment variables.")
	}
	client := vt.NewClient(APIKey)
	fmt.Print("Enter a link here: ")
	var link string
	fmt.Scanln(&link)
	fmt.Println("You entered:", link)
	fmt.Println("Scanning the link...")
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
		fmt.Print("Press Enter to continue...")
		fmt.Scanln()
	}

}
