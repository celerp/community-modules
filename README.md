# Celerp community modules

A directory of community-built modules for [Celerp](https://www.celerp.com).
Every feature in Celerp is a module; these are ones the community has shared.

## Important: how trust works here

**This is an index, not a code host.** Each module lives in its author's own
repository. Celerp does **not** review, host, sign, or warrant the modules
listed here. **A listing is not an endorsement.**

Modules are third-party software that runs with the same access as Celerp
itself. Treat one like anything else you install: read the code, or decide you
trust the author. This is the same trust model as pip, npm, or browser
extensions.

**Celerp never fetches module code automatically.** Installing a module is
always a deliberate act you take on your own machine - that's a security
property, and a deliberate one.

## Install a module

1. Open the module's own repository (linked in the list below) and download it.
2. Copy the module folder into your Celerp data directory's `modules/` folder:
   - **macOS**: `~/Library/Application Support/Celerp/celerp-data/modules/`
   - **Linux**: `~/.config/Celerp/celerp-data/modules/`
   - **Windows**: `%APPDATA%\Celerp\celerp-data\modules\`
3. In Celerp, open **Settings → Modules**, enable it, and restart.

## The modules

<!-- Add your module by opening a PR that adds one row. Keep the list alphabetical. -->

| Module | What it does | Repository | Author | License |
|---|---|---|---|---|
| Equipment Maintenance | Track company equipment and what's due for service | [celerp-module-template](https://github.com/celerp/celerp-module-template) | Celerp | MIT |

## List your module

Build against the [module template](https://github.com/celerp/celerp-module-template),
publish it in **your own** public repository, then open a PR here that adds one
row to the table above. Before it's merged, a listing must:

- link to a repository whose **source is readable**, so users can review what
  they install (this is the whole trust model);
- state a **clear license**. Open-source (MIT, Apache) is welcome; a
  source-available "free to use, no resale" license is equally fine - keep your
  commercial rights if you plan to sell a version later. Just make it clear what
  users may do;
- have a README stating **what data the module touches** and disclosing **any
  network calls**;
- **not** use the `celerp-` name prefix - that namespace is reserved for
  official modules, so users can tell first-party from community at a glance;
- pass `python lint.py <module-folder>` from the template (manifest is valid,
  no imports of Celerp's revenue-gated internals).

Review is of the **listing row**, not the code - see the trust section above.
Listings are removed if a module turns out to be malicious, abandoned, or
misrepresented.

## What comes next

- **Listed** (this repo): community-built, author-hosted, install it yourself.
- **Verified** (planned): a future marketplace with signed, version-pinned,
  reviewed modules. Installing will still be explicit.
- **Bundled**: a standout module may, in collaboration with its author, be
  adopted into the official Celerp distribution - the same way every built-in
  feature already is a module. Authors keep their copyright and license;
  anything further is arranged with the author directly.

Listing here is free and a good way to build an audience first. You are not
required to give your work away to do it: license your module however you like,
open-source or source-available and commercial. The Verified marketplace on the
roadmap is where selling paid modules will live, so a free or trial listing here
can be the on-ramp to a paid version later.

## Security

To report a security issue in a listed module, contact the module's author
first. For issues in Celerp itself, see <https://www.celerp.com> support.
