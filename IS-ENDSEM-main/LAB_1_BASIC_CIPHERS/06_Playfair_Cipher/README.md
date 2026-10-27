# Playfair cipher

## What it does

Encrypt digraphs with a 5x5 key square.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/playfair.py`
- `modifications/02_preserve_spaces.py`

## Reusable blocks

Input/encoding -> core Playfair cipher operation -> inverse/verification -> output.

## Know before modifying

Understand Same row: right; same column: down; rectangle: swap columns, representation conversions, parameter validation, and the difference between a demonstration and production security.
