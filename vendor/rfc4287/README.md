# RFC 4287 RELAX NG Compact schema (Atom Syndication Format)

`atom.rnc` is Appendix B of RFC 4287, "The Atom Syndication Format" (M. Nottingham, Ed., R. Sayre, Ed.,
December 2005). CI uses it to validate `feed.xml` (`.github/scripts/validate_atom.py`) so the check does not
depend on rfc-editor.org being reachable.

- Source: <https://www.rfc-editor.org/rfc/rfc4287.txt>, retrieved 2026-11-11.
- SHA-256 of the retrieved RFC text: `3bd71d76289560c9e860151f39cebbdc402cfd8b788a62048d8dc42824f2d89c`.
- SHA-256 of `atom.rnc`: `8cb943cbffba3649893865d24e083954cb2b03c2f9b63338eb06707fd3a59e78`
  (a test fails if the file changes without this line changing).
- Extraction: the text from the line `# -*- rnc -*-` up to "Authors' Addresses", with the RFC page headers and
  footers ("Nottingham & Sayre ... [Page N]", "RFC 4287 ... December 2005") and form feeds removed, each line
  stripped of its three-space indentation, and runs of blank lines collapsed. Nothing in the grammar was edited.
- The RFC marks the appendix "informative"; the normative text is the RFC body.

## Licence

This file is a copy of part of an IETF document. The RFC's own notice reads:

> Copyright (C) The Internet Society (2005).
>
> This document is subject to the rights, licenses and restrictions contained in BCP 78, and except as set
> forth therein, the authors retain all their rights.

The repository's licences (Apache-2.0 for code, CC BY 4.0 for data) do not apply to this directory. The RFC
states no licence beyond BCP 78, and this project makes no claim about what BCP 78 permits for this excerpt
beyond what the notice above says. The file is used only as a test input and is not published on the site.
