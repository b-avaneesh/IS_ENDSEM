# MD5/SHA-1/SHA-256 experiment

## What it does

Time hashes and detect duplicate digest values.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/hash_benchmark.py`
- `modifications/02_hash_benchmark.py`

## Reusable blocks

Input/encoding -> core MD5/SHA-1/SHA-256 experiment operation -> inverse/verification -> output.

## Know before modifying

Understand digest=H(message); collision if unequal messages share digest, representation conversions, parameter validation, and the difference between a demonstration and production security.
