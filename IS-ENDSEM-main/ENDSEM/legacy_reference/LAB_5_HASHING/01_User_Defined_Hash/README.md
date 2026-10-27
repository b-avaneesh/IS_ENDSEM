# User-defined 32-bit hash

## What it does

Implement the manual-defined 5381/33 hash with bit mixing.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/02_custom_hash.py`
- `modifications/custom_hash.py`

## Reusable blocks

Input/encoding -> core User-defined 32-bit hash operation -> inverse/verification -> output.

## Know before modifying

Understand h=5381; update per character; mask to 32 bits, representation conversions, parameter validation, and the difference between a demonstration and production security.
