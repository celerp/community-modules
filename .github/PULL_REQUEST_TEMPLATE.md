<!-- Adding or updating your module in the directory? Change one entry in
     index.json, then run `python3 scripts/gen_readme.py` to regenerate the
     README table. See "List your module" in the README for what the automatic
     check requires. -->

**Module name:**
**Repository (public URL):**
**Commit (full 40 characters):**
**License:**
**What data it touches / network calls it makes:**

Checklist:
- [ ] I am opening this from the GitHub account that owns the repository
- [ ] The repository is public and `commit` is on its default branch
- [ ] An update points `commit` at a new commit
- [ ] The license matches the repository's license file and the manifest
- [ ] The module README states what data it touches and any network calls
- [ ] The name does **not** start with `celerp-`
- [ ] `python lint.py <module-folder>` from the template passes
- [ ] I changed one `index.json` entry with `"tier": "community"`, declaring `data_access` and `network_calls`
- [ ] `python3 scripts/validate_index.py` passes and I ran `python3 scripts/gen_readme.py`
