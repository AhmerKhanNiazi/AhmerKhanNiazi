import json
import urllib.request
import re

def get_latest_cves():
    url = "https://cve.circl.lu/api/last"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            
        cves = []
        for item in data:
            try:
                severity_level = item.get('database_specific', {}).get('severity', '')
                if severity_level.upper() in ['HIGH', 'CRITICAL']:
                    cve_id = item.get('aliases', [item['id']])[0]
                    summary = item.get('details', '')[:80].replace('\n', ' ') + '...'
                    cves.append({
                        'id': cve_id,
                        'summary': summary,
                        'cvss': severity_level.upper(),
                        'published': item.get('published', '').split('T')[0]
                    })
                if len(cves) >= 5:
                    break
            except Exception:
                continue
        return cves
    except Exception as e:
        print(f"Error fetching CVEs: {e}")
        return []

def update_readme():
    cves = get_latest_cves()
    if not cves:
        print("No CVEs found or API failed.")
        return

    table_content = "### 🔴 LIVE THREAT INTEL FEED (High/Critical)\n\n"
    table_content += "| CVE ID | CVSS Score | Date | Summary |\n"
    table_content += "|---|---|---|---|\n"
    for cve in cves:
        table_content += f"| **{cve['id']}** | 🔥 {cve['cvss']} | {cve['published']} | {cve['summary']} |\n"

    with open('README.md', 'r', encoding='utf-8') as f:
        content = f.read()

    # The markers in README.md will be <!-- THREAT_FEED_START --> and <!-- THREAT_FEED_END -->
    new_content = re.sub(
        r'<!-- THREAT_FEED_START -->.*<!-- THREAT_FEED_END -->',
        f'<!-- THREAT_FEED_START -->\n{table_content}\n<!-- THREAT_FEED_END -->',
        content,
        flags=re.DOTALL
    )

    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print("README.md updated successfully with latest threats.")

if __name__ == "__main__":
    update_readme()
