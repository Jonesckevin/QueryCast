# QueryCast — Universal SIEM Query Translator

Fast offline web tool to convert Sigma rules and SIEM queries across multiple SIEM platforms and EDR tools.

## Features
| Feature | Description |
| --- | --- |
| Sigma Rule Conversion | Convert Sigma rules to various SIEM query languages (Splunk SPL, Elastic EQL) |
| Query Translation | Translate queries between different SIEM platforms |
| Batch IOC Conversion | Convert lists of IOCs (IPs, domains, hashes) into SIEM-specific query formats |
| Offline Functionality | Fully client-side, no server required |
| Dockerized | Easy deployment with Docker |
| Extensible | Modular architecture for adding new conversion operators |
| User-Friendly UI | Clean interface for quick conversions |
| Syntax Highlighting | Output is highlighted for better readability |
| Export Options | Save converted queries in various formats (TXT, JSON, etc.) |
| Ai Assisted Suggestions | Online or Custom Offline LLM support for query optimization. |
 

## Quick Start

1. Clone or download the project:
   ```bash
   git clone github.com/jonesckevin/QueryCast
   cd QueryCast
   ```

2. Open `index.html` in your browser:
   ```bash
   # Linux
   xdg-open index.html
   
   # Windows
   start index.html
   ```

   Or use a local server:
   ```bash
   npx http-server -p 8080 -o
   ```

3. Start converting!
   - Paste a Sigma rule, query, or IOC
   - Choose a conversion operator (e.g., "Splunk SPL")
   - Get instant output

### Docker Compose

```bash
docker-compose up --build
```

### Docker Run
```bash
docker build -t querycast:latest .
docker run -d -p 4007:8080 --name querycast querycast:latest
```

### Docker Hub Pull
```bash
docker pull jonesckevin/querycast:latest
docker run -d -p 4007:8080 --name querycast jonesckevin/querycast:latest
```

Then open http://localhost:4007.
