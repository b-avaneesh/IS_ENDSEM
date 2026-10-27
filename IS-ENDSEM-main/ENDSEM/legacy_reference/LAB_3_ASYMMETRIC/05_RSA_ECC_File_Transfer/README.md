# RSA/ECC file-transfer study

## What it does

Demonstrate hybrid file protection and timing concepts.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/02_hybrid_file.py`
- `modifications/RSA_VS_ECC.py`

## Reusable blocks

Input/encoding -> core RSA/ECC file-transfer study operation -> inverse/verification -> output.

## Know before modifying

Understand Public-key agreement/wrapping + symmetric file encryption, representation conversions, parameter validation, and the difference between a demonstration and production security.
