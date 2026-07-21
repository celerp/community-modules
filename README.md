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
2. In Celerp, open the **Modules** section. On the **Local Modules** tab, use
   **Import Module** to add the zip you downloaded, or point it at an unzipped
   module folder. You can also copy the module folder into your Celerp data
   directory's `modules/` folder by hand:
   - **macOS**: `~/Library/Application Support/Celerp/celerp-data/modules/`
   - **Linux**: `~/.config/Celerp/celerp-data/modules/`
   - **Windows**: `%APPDATA%\Celerp\celerp-data\modules\`
3. Enable the module, then restart Celerp.

If the module does not appear after restarting, there are two usual causes:
it landed somewhere other than the exact path above (the capitalisation matters
on Linux), or it fails the template's `lint.py`, which reports what is wrong
with the manifest.

## The modules

The machine-readable catalog is [`index.json`](index.json); Celerp's in-app
Marketplace tab and the table below are both generated from it. **Official**
modules are built and sold by Celerp. **Community** modules are third-party,
exactly as described above.

<!-- The table below is generated from index.json by scripts/gen_readme.py. Edit index.json, not the table. -->
<!-- modules:begin -->
| Module | Tier | What it does | Source | Author | License |
|---|---|---|---|---|---|
| Equipment Maintenance | Community | Track company equipment and what's due for service. | [celerp/celerp-module-template](https://github.com/celerp/celerp-module-template) | Celerp | MIT |
<!-- modules:end -->

## List your module

Build against the [module template](https://github.com/celerp/celerp-module-template),
publish it in **your own** public repository, then open a PR here that adds one
entry to [`index.json`](index.json). The README table above is generated from
that file, so there is nothing to edit by hand.

Your `index.json` entry looks like this. Keep official entries first, in their
existing order, then community entries by `id`, so the file and the generated
table sort the same way:

```json
{
  "id": "acme-widgets",
  "name": "Acme Widgets",
  "description": "One sentence on what it does.",
  "tier": "community",
  "version": "0.1.0",
  "repo": "https://github.com/acme/acme-widgets",
  "author": "Acme",
  "license": "MIT",
  "data_access": "Which tables it reads and writes, and nothing else.",
  "network_calls": "Every outbound call it makes, or 'None.'"
}
```

Before it's merged, a listing must:

- link to a repository whose **source is readable**, so users can review what
  they install (this is the whole trust model);
- state a **clear license**. Open-source (MIT, Apache) is welcome; a
  source-available "free to use, no resale" license is equally fine - keep your
  commercial rights if you plan to sell a version later. Just make it clear what
  users may do;
- declare **what data the module touches** (`data_access`) and **any network
  calls** (`network_calls`), and state the same in the module's README. Celerp
  shows both on your listing labelled as your own declaration;
- **not** use the `celerp-` name prefix - that namespace is reserved for
  official modules, so users can tell first-party from community at a glance;
- carry a **version** that matches the `version` in the module's
  `PLUGIN_MANIFEST`, so the listed version and the installed one stay in step;
- use `"tier": "community"`. The `verified` and `official` tiers are set by the
  maintainer of this directory, not chosen by a contributor;
- pass `python lint.py <module-folder>` from the template (manifest is valid,
  no imports of Celerp's revenue-gated internals) and
  `python3 scripts/validate_index.py` from this repo (the entry is well-formed
  and correctly ordered).

Review is of the **listing**, not the code - see the trust section above.
Listings are removed if a module turns out to be malicious, abandoned, or
misrepresented; removal is a PR that takes the entry back out, and it reaches
installed apps within minutes.

## Sell your module

Listing here is free and always will be. If you want to charge for a module,
you sell it through Celerp's marketplace rather than through this directory:

1. Sign in with GitHub on the Celerp authors page. The GitHub account must be
   the one that owns the listed repository.
2. Connect a Stripe account that can accept charges. Buyers pay you directly
   and Stripe handles payouts, so you keep your own customer relationship.
3. Publish your module with a price. Paid modules are security-scanned before
   Celerp will distribute them, so there is a short review between publishing
   and the first sale.
4. The maintainer moves your entry to the `verified` tier and records the price
   in `index.json`. That tier is what carries a Buy button. Community entries
   take no price - the directory's own check rejects one - so they always list
   as free, installed straight from the author's repository.

Three things are refused, so it is worth knowing them before you start:
publishing before your Stripe account can actually accept charges, a name
starting with `celerp-`, and a name another author has already taken. Pick your
vendor prefix early.

You can stop selling at any time by unpublishing; the listing stays until you
or the maintainer take it out.

## How listings work

- **community** (this repo): built by the community, hosted by their authors,
  installed by hand from the author's repository. Free to list. Celerp does not
  review the code.
- **verified**: a third-party module sold through Celerp's marketplace. Scanned
  before distribution, bought and installed in-app. The tier is set by Celerp,
  never self-assigned.
- **official**: built and maintained by Celerp.

A standout community module may, in collaboration with its author, be adopted
into the official Celerp distribution - the same way every built-in feature
already is a module. Authors keep their copyright and license; anything further
is arranged with the author directly.

## Security

To report a security issue in a listed module, contact the module's author
first. For issues in Celerp itself, see <https://www.celerp.com> support.
