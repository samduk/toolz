I used the following one liner and broken it down to come up with the script. 

```
curl -s -X GET https://www.virustotal.com/api/v3/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -H "x-apikey:f41277fd391d1a80fc4XXXXXXXXXXXXXXXXXX" | jq -r '.data.attributes.last_analysis_stats.malicious'
```


