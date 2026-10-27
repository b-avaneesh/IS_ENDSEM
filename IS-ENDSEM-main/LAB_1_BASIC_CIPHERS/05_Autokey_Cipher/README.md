# Autokey cipher

## What it does

Extend a numeric seed with plaintext letters.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/02_preserve_spaces.py`
- `modifications/autokey.py`

## Reusable blocks

Input/encoding -> core Autokey cipher operation -> inverse/verification -> output.

## Know before modifying

Understand Keystream = seed followed by plaintext values, representation conversions, parameter validation, and the difference between a demonstration and production security.
