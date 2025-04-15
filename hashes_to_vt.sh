#!/usr/bin/env bash

# VirusTotal API Key: Set it here or via environment variable
VT_API_KEY="${VT_API_KEY:-f41277fd391d1a80fc4cfbf0afae5184d4300b1cf0891adfd0d62a8ab3f945b3}"

# Adjustable delay to respect API rate limit (default: 15 seconds)
RATE_LIMIT_DELAY=15

# Input file containing hashes
INPUT_FILE="hashes.txt"

# Output file for results
OUTPUT_FILE="vt_results.txt"

# Check prerequisites
if [[ -z "$VT_API_KEY" || "$VT_API_KEY" == "redacted" ]]; then
  echo "❌ Error: VirusTotal API key is missing. Set it in the script or as an environment variable (VT_API_KEY)."
  exit 1
fi

if [[ ! -f "$INPUT_FILE" ]]; then
  echo "❌ Error: File '$INPUT_FILE' not found!"
  exit 1
fi

# VirusTotal API base URL
API_URL="https://www.virustotal.com/api/v3/files/"

# Clear output file
> "$OUTPUT_FILE"

# Process each hash
while IFS= read -r hash || [[ -n "$hash" ]]; do
  # Skip empty lines and comments
  [[ -z "$hash" || "$hash" == \#* ]] && continue

  echo -e "\n🔍 Checking hash: $hash"
  echo "Hash: $hash" >> "$OUTPUT_FILE"

  response=$(curl -s -X GET "${API_URL}${hash}" \
    -H "x-apikey: ${VT_API_KEY}")

  if echo "$response" | jq -e .error > /dev/null; then
    echo "❌ Error in response: $(echo "$response" | jq -r '.error.message')" | tee -a "$OUTPUT_FILE"
  else
    detected=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.malicious')

    if [[ "$detected" -gt 0 ]]; then
      echo -e "⚠️  \e[31mDetected by $detected antivirus engines\e[0m" | tee -a "$OUTPUT_FILE"
      echo "Engines:" >> "$OUTPUT_FILE"
      echo "$response" | jq -r '.data.attributes.last_analysis_results | to_entries[] | select(.value.category == "malicious") | "  - \(.key)"' | tee -a "$OUTPUT_FILE"
    else
      echo -e "✅ \e[32mNo threats detected\e[0m" | tee -a "$OUTPUT_FILE"
    fi
  fi

  echo "-----------------------------" | tee -a "$OUTPUT_FILE"

  # Respect rate limit
  sleep "$RATE_LIMIT_DELAY"

done < "$INPUT_FILE"

