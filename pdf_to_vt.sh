#!/usr/bin/env bash

# you have to create virustotal account and get the free API key from there. I have redacted mine. 
VT_API_KEY="redacted"

# Check if API key is set
if [[ -z "$VT_API_KEY" ]]; then
  echo "Error: VirusTotal API key is missing. Set it in the script or as an environment variable."
  exit 1
fi

# You have to generate the hashe values of the suspicious PDF files and store the value and name the file as hashes.txt 
INPUT_FILE="hashes.txt"

# Check if file exists
if [[ ! -f "$INPUT_FILE" ]]; then
  echo "Error: File '$INPUT_FILE' not found!"
  exit 1
fi

# VirusTotal API URL
API_URL="https://www.virustotal.com/api/v3/files/"

# Read each hash from the file and check with VirusTotal
while read -r hash; do
  echo "Checking hash: $hash"

  # Send API request
  response=$(curl -s -X GET "${API_URL}${hash}" \
    -H "x-apikey: ${VT_API_KEY}")

  # Extract the detection status
  detected=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.malicious')

  if [[ "$detected" -gt 0 ]]; then
    echo "⚠️ Detected by $detected antivirus engines"
    
    # Extract antivirus engines that flagged the file
    echo "Detected by:"
    echo "$response" | jq -r '.data.attributes.last_analysis_results | to_entries[] | select(.value.category == "malicious") | "\(.key)"'
  else
    echo "✅ No threats detected"
  fi

  echo "-----------------------------"

  # Avoid hitting API rate limits
  sleep 15

done < "$INPUT_FILE"

