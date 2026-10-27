# Classical cipher attacks

## What it does

Demonstrate brute-force and known-plaintext attacks from Lab 1 exercises.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/attacks.py`
- `modifications/02_attacks.py`

## Reusable blocks

Input/encoding -> core Classical cipher attacks operation -> inverse/verification -> output.

## Know before modifying

Understand Try valid keys; use plaintext/ciphertext equations modulo 26, representation conversions, parameter validation, and the difference between a demonstration and production security.
