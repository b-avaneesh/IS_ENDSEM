# Affine cipher

## What it does

Combine multiplication and addition modulo 26.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/02_preserve_spaces.py`
- `modifications/affine.py`

## Reusable blocks

Input/encoding -> core Affine cipher operation -> inverse/verification -> output.

## Know before modifying

Understand C = (aP + b) mod 26; P = a^-1(C-b) mod 26, representation conversions, parameter validation, and the difference between a demonstration and production security.
