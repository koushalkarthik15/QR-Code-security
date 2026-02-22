1. Ingest QR payloads and extract URLs.
2. Canonicalize URLs (lowercase host remove default ports normalize encoding strip fragments).
3. Resolve redirects with hop and timeout limits.
4. Parse URL components (scheme host path query tld etld_plus_one).
5. Generate lexical and statistical features.
6. Handle invalid or missing values deterministically.
7. Deduplicate by canonical URL and near duplicates.
8. Remove leakage-prone columns from modeling view.
9. Split by time and etld_plus_one to reduce leakage.
10. Export cleaned and feature artifacts.
