# RSA, ElGamal and Rabin comparison

## What it does

Compare core integer operations and timing.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/compare.py`
- `modifications/02_compare.py`

## Reusable blocks

Input/encoding -> core RSA, ElGamal and Rabin comparison operation -> inverse/verification -> output.

## Know before modifying

Understand RSA exponentiation; ElGamal discrete-log construction; Rabin squaring, representation conversions, parameter validation, and the difference between a demonstration and production security.
