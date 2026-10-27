# ElGamal signature

## What it does

Sign and verify an integer message using ElGamal.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/02_elgamal_signature.py`
- `modifications/elgamal_schnorr_signature.py`

## Reusable blocks

Input/encoding -> core ElGamal signature operation -> inverse/verification -> output.

## Know before modifying

Understand r=g^k mod p; s=k^-1(H(m)-xr) mod p-1, representation conversions, parameter validation, and the difference between a demonstration and production security.
