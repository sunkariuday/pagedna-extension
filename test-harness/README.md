# PageDNA fixture lab

Serve this directory over HTTP:

```bash
python -m http.server 8080 --directory test-harness
```

Open `http://localhost:8080/example-site.html`, create a PageDNA baseline, reload, then use one fixture button at a time. Harmless styling should not create a security alert; iframe, script, and form-destination changes should create evidence-backed diffs.
