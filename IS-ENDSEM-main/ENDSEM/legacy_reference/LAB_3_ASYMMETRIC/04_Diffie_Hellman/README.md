# Diffie-Hellman key exchange

## What it does

Compute a common secret over an insecure channel.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/diffie_hellman.py`
- `modifications/02_diffie_hellman.py`

## Reusable blocks

Input/encoding -> core Diffie-Hellman key exchange operation -> inverse/verification -> output.

## Know before modifying

Understand A=g^a mod p; B=g^b mod p; K=B^a=A^b mod p, representation conversions, parameter validation, and the difference between a demonstration and production security.
