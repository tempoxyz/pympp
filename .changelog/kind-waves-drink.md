---
pympp: patch
---

Fixed Zone payments so a withdrawal that settles after its Challenge expires is never paid twice, and a server accepts its late credential only within an explicitly configured grace. Once a server accepts that credential, a new Challenge with the same terms pays again.
