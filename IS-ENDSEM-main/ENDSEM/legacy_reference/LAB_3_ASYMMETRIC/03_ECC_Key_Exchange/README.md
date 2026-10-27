# Elliptic-curve key exchange

## What it does

Use ECDH to derive the same shared secret at two peers.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/02_ecc_ecdh.py`
- `modifications/ECC.py`

## Reusable blocks

Input/encoding -> core Elliptic-curve key exchange operation -> inverse/verification -> output.

## Know before modifying

Understand Q=dG; shared secret=d_A Q_B=d_B Q_A, representation conversions, parameter validation, and the difference between a demonstration and production security.
