# CIA triad demonstration

## What it does

Combine encryption, hashing, and signatures as requested in Lab 6.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/cia_demo.py`
- `modifications/02_cia_demo.py`

## Reusable blocks

Input/encoding -> core CIA triad demonstration operation -> inverse/verification -> output.

## Know before modifying

Understand Encrypt for confidentiality; hash/sign for integrity/authenticity, representation conversions, parameter validation, and the difference between a demonstration and production security.
