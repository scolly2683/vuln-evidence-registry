# Comparison: `heldout/candidates/sonnet-2026-09-03` vs reference `heldout/reference`

29 CVEs compared, 1 missing from candidate (CVE-2022-41328).

| scope | CVEs | ref #pre | cand #pre | cite_valid | recall (exact) | recall (cont.) | precision (exact) | precision (cont.) | empty_agree | cat_agree | drift | parse_fail |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **all** | 29 | 41 | 43 | 1.00 | 0.60 | 0.94 | 0.58 | 0.94 | 1.00 | 0.86 | 0 | 0 |
| edge | 11 | 20 | 21 | 1.00 | 0.72 | 0.94 | 0.76 | 1.00 | 1.00 | 0.85 | 0 | 0 |
| microsoft | 9 | 6 | 8 | 1.00 | 0.83 | 1.00 | 0.71 | 0.86 | 1.00 | 1.00 | 0 | 0 |
| oss | 9 | 15 | 14 | 1.00 | 0.27 | 0.91 | 0.25 | 0.92 | 1.00 | 0.67 | 0 | 0 |

## 95% intervals (Wilson)

| scope | recall (exact) | recall (cont.) | precision (exact) | empty_agree |
|---|---|---|---|---|
| **all** | 21/35  [0.44, 0.74] | 33/35  [0.81, 0.98] | 21/36  [0.42, 0.73] | 29/29  [0.88, 1.00] |
| edge | 13/18  [0.49, 0.88] | 17/18  [0.74, 0.99] | 13/17  [0.53, 0.90] | 11/11  [0.74, 1.00] |
| microsoft | 5/6  [0.44, 0.97] | 6/6  [0.61, 1.00] | 5/7  [0.36, 0.92] | 9/9  [0.70, 1.00] |
| oss | 3/11  [0.10, 0.57] | 10/11  [0.62, 0.98] | 3/12  [0.09, 0.53] | 9/9  [0.70, 1.00] |

**Verdict:** NOT acceptable as-is (thresholds: cite_valid ≥0.95, recall ≥0.80, empty_agree ≥0.90).
A verdict read off a point estimate is a verdict on the midpoint of [0.44, 0.74] — read the interval before acting on the word above.

## Per CVE

| CVE | stratum | ref #pre | cand #pre | cand cites valid | recall | precision | empty agree | note |
|---|---|---|---|---|---|---|---|---|
| CVE-2010-0806 | microsoft | 0 | 0 | 0/0 |  |  | ✓ |  |
| CVE-2013-2251 | oss | 0 | 0 | 0/0 |  |  | ✓ |  |
| CVE-2014-2120 | edge | 1 | 1 | 1/1 | 0.00 | 0.00 | ✓ |  |
| CVE-2016-3088 | oss | 2 | 1 | 1/1 | 0.00 | 0.00 | ✓ |  |
| CVE-2016-7262 | microsoft | 0 | 0 | 0/0 |  |  | ✓ |  |
| CVE-2016-8735 | oss | 2 | 2 | 2/2 | 0.00 | 0.00 | ✓ |  |
| CVE-2017-15944 | edge | 1 | 1 | 1/1 | 0.00 | 0.00 | ✓ |  |
| CVE-2017-6742 | edge | 3 | 4 | 4/4 | 1.00 | 1.00 | ✓ |  |
| CVE-2019-12989 | edge | 0 | 0 | 0/0 |  |  | ✓ |  |
| CVE-2019-12991 | edge | 0 | 0 | 0/0 |  |  | ✓ |  |
| CVE-2020-1631 | edge | 4 | 4 | 4/4 | 1.00 | 1.00 | ✓ |  |
| CVE-2021-20035 | edge | 2 | 2 | 2/2 | 1.00 | 1.00 | ✓ |  |
| CVE-2021-22893 | edge | 2 | 2 | 2/2 | 0.00 | 0.00 | ✓ |  |
| CVE-2021-42013 | oss | 3 | 3 | 3/3 | 1.00 | 1.00 | ✓ |  |
| CVE-2021-45046 | oss | 2 | 2 | 2/2 | 0.00 | 0.00 | ✓ |  |
| CVE-2022-0028 | edge | 5 | 5 | 5/5 | 0.80 | 1.00 | ✓ |  |
| CVE-2022-0492 | oss | 1 | 1 | 1/1 | 0.00 | 0.00 | ✓ |  |
| CVE-2022-1388 | edge | 1 | 1 | 1/1 | 1.00 | 1.00 | ✓ |  |
| CVE-2022-22947 | oss | 3 | 3 | 3/3 | 0.00 | 0.00 | ✓ |  |
| CVE-2022-42475 | edge | 1 | 1 | 1/1 | 0.00 | 0.00 | ✓ |  |
| CVE-2023-29336 | microsoft | 0 | 0 | 0/0 |  |  | ✓ |  |
| CVE-2023-35311 | microsoft | 1 | 1 | 1/1 | 1.00 | 1.00 | ✓ |  |
| CVE-2023-36761 | microsoft | 1 | 2 | 2/2 | 1.00 | 0.50 | ✓ |  |
| CVE-2024-23897 | oss | 1 | 1 | 1/1 | 0.00 | 0.00 | ✓ |  |
| CVE-2026-21514 | microsoft | 1 | 1 | 1/1 | 1.00 | 1.00 | ✓ |  |
| CVE-2026-21525 | microsoft | 1 | 2 | 2/2 | 0.00 | 0.00 | ✓ |  |
| CVE-2026-31431 | oss | 1 | 1 | 1/1 | 0.00 | 0.00 | ✓ |  |
| CVE-2026-45498 | microsoft | 1 | 1 | 1/1 | 1.00 | 1.00 | ✓ |  |
| CVE-2026-50522 | microsoft | 1 | 1 | 1/1 | 1.00 | 1.00 | ✓ |  |
