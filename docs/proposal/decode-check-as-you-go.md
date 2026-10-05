# Proposal: check decoded text as it is produced

Status: proposed. Tracked by the known-gap test `gap_printable_decoys_starve_variant_budget` in `crates/core/src/decode.rs` and the TODO above `MAX_VARIANTS`.

## Problem

The fast scan decodes encoded text (base64, hex, URL escapes, HTML entities, rot13) before looking for injection phrases and secrets. It works in two steps: first it collects decoded versions into a list of at most 8 entries, then it checks that list.

The 8-entry limit keeps a hostile input from making the scanner decode forever. But it counts results that were kept, not work done. An attacker can fill all 8 entries with harmless decoded text, so the real payload never gets decoded:

```
input:  [decoy0] ... [decoy7] [PAYLOAD]       (prose between the blobs)

step 1: decode_variants() fills the list
        ┌────────┬────────┬────────┬─────┬────────┐
        │ text   │ decoy0 │ decoy1 │ ... │ decoy6 │   full
        └────────┴────────┴────────┴─────┴────────┘
        PAYLOAD would be next, but there is no room, so it is never decoded

step 2: scan_text_fast() checks each entry
        text: clean, decoy0: clean, ..., decoy6: clean
        result: Clean   (payload missed)
```

Each decoy only has to decode to valid text. Eight small base64 blobs such as `base64("harmless note number 0")` are enough. This predates the whole-token decoding added for B1: base64 blobs separated by prose did the same thing before. The ML scan still sees the input, but only in its encoded form.

## Proposal

Check each decoded value the moment it is produced, and stop at the first hit. Nothing is kept, so there is no list to fill. The safety limit becomes a cap on total work instead of a count of results.

```
decode decoy0   check: clean, keep going
decode decoy1   check: clean, keep going
   ...
decode decoy7   check: clean, keep going
decode PAYLOAD  check: INJECTION, stop
result: Injection
```

## Why this is a design change, not a one-liner

Raising the limit from 8 to something larger only moves the problem: the attacker adds more decoys. The fix has to change what the limit counts, and that touches the interface, the limit itself and its cost.

### 1. The interface changes

`decode_variants` returns a list today. Two callers loop over it, each with a different check:

```
             today                                  proposed
  ┌──────────────────────────┐        ┌───────────────────────────────┐
  │ decode_variants(text)    │        │ decode_until(text, check)     │
  │   returns Vec<String>    │        │   stops when check is true    │
  │   (at most 8)            │        │                               │
  └────────────┬─────────────┘        └───────────────────────────────┘
               │ used by 2 callers in crates/core/src/lib.rs
       ┌───────┴─────────┐
  scan_injection_only  scan_text_fast       each caller passes its check in
  (security phrases)   (secret patterns)    instead of looping over a list
```

Callers to update:

- `scan_injection_only` (`crates/core/src/lib.rs`): passes `has_security_substring` as the check.
- `scan_text_fast` (`crates/core/src/lib.rs`): passes `has_secret` as the check.
- `crates/core/tests/properties.rs`: `decode_variants_is_bounded` and `decode_variants_has_no_duplicates` test the list. They become tests of the work cap and of termination.
- Unit tests in `decode.rs` that assert on the list contents (`embedded_decoding_skips_repeated_variants`, `full_text_decoding_depth_is_bounded` and others). These need a way to observe what was decoded, such as a check closure that records its inputs.

The recursion in `collect_decoded` and `push_decoded` also changes. It must pass the check down and return early on a hit, instead of pushing into a shared list.

### 2. The limit changes meaning

`MAX_VARIANTS = 8` is replaced by a budget on total decoded bytes, for example 1 MB per scan. Every decode attempt that produces text spends its length from the budget. The other existing limits stay:

| Limit | Today | Proposed |
|---|---|---|
| Kept results | `MAX_VARIANTS = 8` | removed |
| Total decoded bytes | none | new budget, value to be measured |
| Nesting depth | `MAX_DECODE_DEPTH = 6` | unchanged |
| Size of one base64 or hex decode | `MAX_DECODED_BYTES = 64 KB` | unchanged |

Duplicate tracking also needs a new home. Today `variants.contains(..)` both deduplicates and stops the rot13 back-and-forth cycle. Without the list, a small set of hashes of already-checked strings would do the same job.

### 3. The cost needs re-measuring

- **Attacks** get faster: the scan stops at the first hit.
- **Clean text** is checked in full either way, so cost should be about the same. The difference is that work is now bounded by bytes rather than by 8 results, and the byte budget must be picked so the worst case stays acceptable.
- Measure the same way B2 and B1 were decided: the worst-case inputs (one large blob, nested layers, many blobs in 1 MB), and the 20k-file corpus for changed verdicts and total time. Today's figures are 0.54s for 1 MB of prose and about 9 ms per file on the corpus.

## Open questions

1. **Budget value.** 1 MB per scan is a starting guess. It should be set from the worst-case measurements, not picked up front.
2. **One pass or two.** The injection and secret checks could share one decode pass with a combined check. That roughly halves decoding cost, but the two passes start from slightly different text: the injection pass maps homoglyphs first. Sharing a pass changes which variants each check sees, so it should be a separate decision.
3. **Order.** Today full-text decodes come first, then randomness windows, then whole tokens, then URL and HTML escapes, then rot13. With a byte budget instead of a slot count, order only matters once the budget runs out, but it is worth keeping the cheapest and most likely decoders first.

## Done when

- `gap_printable_decoys_starve_variant_budget` is flipped and renamed to describe the fixed behaviour.
- All existing decode tests pass, rewritten where they asserted on list contents.
- Worst-case timings and the corpus run show no verdict changes and acceptable cost.
- The TODO above `MAX_VARIANTS` in `crates/core/src/decode.rs` is removed.
