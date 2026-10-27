# ElGamal encryption

## What it does

Encrypt/decrypt integer-encoded characters with ElGamal.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/02_elgamal.py`
- `modifications/elgamal.py`

## Reusable blocks

Input/encoding -> core ElGamal encryption operation -> inverse/verification -> output.

## Know before modifying

Understand c1=g^k mod p; c2=m*y^k mod p, representation conversions, parameter validation, and the difference between a demonstration and production security.
