package trivy

# Legal exceptions must identify the exact package and version (and file path
# when the finding has one), state the rationale and expiry in this file, and
# receive CODEOWNERS approval. Never suppress a license ID globally: Trivy
# cannot path-scope OS-package entries. The allowlist is intentionally empty:
# the locked production npm graph has no reciprocal-license finding, and any
# future finding must block release until removed or narrowly approved.
default ignore = false
