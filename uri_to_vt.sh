#!/usr/bin/env bash

# You have to create a VirusTotal account and get the free API key from there. I have redacted mine.
VT_API_KEY="redacted"

# Check if API key is set
if [[ -z "$VT_API_KEY" ]]; then
  echo "Error: VirusTotal API key is missing. Set it in the script or as an environment variable."
  exit 1
fi

# Input file containing URLs (one URL per line)
INPUT_FILE="cleaned_uri.txt"

# Check if file exists
if [[ ! -f "$INPUT_FILE" ]]; then
  echo "Error: File '$INPUT_FILE' not found!"
  exit 1
fi

# VirusTotal API URL for URLs
API_URL="https://www.virustotal.com/api/v3/urls/"

# Read each URL from the file and check with VirusTotal
while read -r url; do
  # Encode the URL in base64 as required by VirusTotal API
  encoded_url=$(echo -n "$url" | base64 | tr -d '\n')

  echo "Checking URL: $url"

  # Send API request
  response=$(curl -s -X GET "${API_URL}${encoded_url}" \
    -H "x-apikey: ${VT_API_KEY}")

  # Extract the detection status
  detected=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.malicious')

  if [[ "$detected" -gt 0 ]]; then
    echo "⚠️ Detected by $detected antivirus engines"
    
    # Extract antivirus engines that flagged the URL
    echo "Detected by:"
    echo "$response" | jq -r '.data.attributes.last_analysis_results | to_entries[] | select(.value.category == "malicious") | "\(.key)"'
  else
    echo "✅ No threats detected"
  fi

  echo "-----------------------------"

  # Avoid hitting API rate limits
  sleep 15

done < "$INPUT_FILE"

