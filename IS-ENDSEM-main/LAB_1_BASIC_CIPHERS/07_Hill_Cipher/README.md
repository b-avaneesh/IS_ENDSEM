# Hill cipher

## What it does

Encrypt fixed-size letter vectors using matrix multiplication mod 26.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/02_hill.py`
- `modifications/hill.py`

## Reusable blocks

Input/encoding -> core Hill cipher operation -> inverse/verification -> output.

## Know before modifying

Understand C = KP mod 26; P = K^-1 C mod 26, representation conversions, parameter validation, and the difference between a demonstration and production security.
