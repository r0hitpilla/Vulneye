# VulnEye Architecture

1. Fetchers
   - NVD fetcher: queries NVD REST API
   - CISA KEV fetcher: pulls known exploited vulnerabilities feed

2. Matcher
   - Loads a local asset inventory (JSON)
   - Heuristic matching based on product names and versions

3. Report generator
   - Generates HTML report with severity and remediation

4. Automation
   - GitHub Actions runs nightly and saves report artifacts
