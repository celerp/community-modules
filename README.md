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

The machine-readable catalog is [`index.json`](index.json); Celerp's in-app
Marketplace tab and the table below are both generated from it. **Official**
modules are built and sold by Celerp. **Community** modules are third-party,
exactly as described above.

<!-- The table below is generated from index.json by scripts/gen_readme.py. Edit index.json, not the table. -->
<!-- modules:begin -->
| Module | Tier | What it does | Source | Author | License |
|---|---|---|---|---|---|
| Budgeting | Official | Budget entry per GL account, actual vs budget variance analysis, and period forecasting. | [celerp.com/marketplace/celerp-budgeting](https://celerp.com/marketplace/celerp-budgeting) | Celerp | Proprietary |
| HR & Payroll | Official | Employee records, payroll processing, leave management, and tax withholding. | [celerp.com/marketplace/celerp-hr](https://celerp.com/marketplace/celerp-hr) | Celerp | Proprietary |
| Multi-Currency | Official | Multi-currency transactions, exchange rate management, and foreign currency revaluation. | [celerp.com/marketplace/celerp-multicurrency](https://celerp.com/marketplace/celerp-multicurrency) | Celerp | Proprietary |
| Point of Sale | Official | Fullscreen POS terminal with scan-to-cart, receipt printing, and cash management. | [celerp.com/marketplace/celerp-pos](https://celerp.com/marketplace/celerp-pos) | Celerp | BSL-1.1 |
| Sales Funnel | Official | Deals pipeline and Kanban board for tracking sales opportunities from lead to close. | [celerp.com/marketplace/celerp-sales-funnel](https://celerp.com/marketplace/celerp-sales-funnel) | Celerp | BSL-1.1 |
| Warehousing | Official | Advanced warehouse operations: pick instructions, stock receipts, reservations, and transfer workflows. | [celerp.com/marketplace/celerp-warehousing](https://celerp.com/marketplace/celerp-warehousing) | Celerp | BSL-1.1 |
| Equipment Maintenance | Community | Track company equipment and what's due for service. | [celerp/celerp-module-template](https://github.com/celerp/celerp-module-template) | Celerp | MIT |
<!-- modules:end -->

## List your module

Build against the [module template](https://github.com/celerp/celerp-module-template),
publish it in **your own** public repository, then open a PR here that adds one
entry to [`index.json`](index.json) (the README table regenerates from it).
Before it's merged, a listing must:

- link to a repository whose **source is readable**, so users can review what
  they install (this is the whole trust model);
- state a **clear license**. Open-source (MIT, Apache) is welcome; a
  source-available "free to use, no resale" license is equally fine - keep your
  commercial rights if you plan to sell a version later. Just make it clear what
  users may do;
- declare in its index entry **what data the module touches** (`data_access`)
  and **any network calls** (`network_calls`), and state the same in its README;
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
