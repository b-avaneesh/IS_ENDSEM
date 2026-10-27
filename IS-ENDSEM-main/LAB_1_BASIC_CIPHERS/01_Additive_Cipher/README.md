# Additive (Caesar/shift) cipher

## What it does

Encrypt/decrypt letters by adding a key modulo 26.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/additive.py`
- `modifications/02_preserve_spaces_additive.py`

## Reusable blocks

Input/encoding -> core Additive (Caesar/shift) cipher operation -> inverse/verification -> output.

## Know before modifying

Understand C = (P + k) mod 26; P = (C - k) mod 26, representation conversions, parameter validation, and the difference between a demonstration and production security.
