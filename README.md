# AitherNet Index

A hand-curated map of the internet, kept in git. Every entry is one JSON file
in `records/`, and every entry says who checked it, when and how.

Live at **https://index.aitherium.com**.

## Look up a keyword

Every entry can carry `.aither` keywords, like an old AOL keyword. To resolve
one, fetch its JSON file:

```
curl https://index.aitherium.com/n/docs.aither.json
```

An unknown name returns 404. The resolver never guesses.

## Add a site

1. Copy any file in `records/` to `records/<id>.json`, where the file name equals the `id`.
2. Fill in `kind` (site, garden, room, space, org, service, gate, world, dataset), the
   `title`, an https `url`, `tags`, and optionally `names` (`*.aither`, lowercase) with a `route`.
3. Link it to other entries with `edges` (`links_to`, `part_of`, `mirrors`, `about`...).
   That is how webrings work here.
4. Say where you found it in `provenance.sources`, and how you checked it in
   `provenance.validated` (`at`, `by`, `method`).
5. Run `python check.py`, which must print 0 findings, then open a pull request.

CI runs the same check. A failing index is never published.

## Licence

Records: CC BY 4.0. Code: MIT. See `LICENSE`.
