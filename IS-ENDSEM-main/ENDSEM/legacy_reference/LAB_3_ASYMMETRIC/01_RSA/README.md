# RSA

## What it does

Generate keys and encrypt/decrypt a short message.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/rsa.py`
- `modifications/02_rsa.py`

## Reusable blocks

Input/encoding -> core RSA operation -> inverse/verification -> output.

## Know before modifying

Understand c = m^e mod n; m = c^d mod n, representation conversions, parameter validation, and the difference between a demonstration and production security.
