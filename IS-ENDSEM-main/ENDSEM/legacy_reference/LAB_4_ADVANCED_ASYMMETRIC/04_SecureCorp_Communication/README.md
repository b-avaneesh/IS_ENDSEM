# SecureCorp scenario

## What it does

Combine RSA identity keys and DH session agreement for subsystems.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/securecorp.py`
- `modifications/02_securecorp.py`

## Reusable blocks

Input/encoding -> core SecureCorp scenario operation -> inverse/verification -> output.

## Know before modifying

Understand Authenticate public values; derive shared session key, representation conversions, parameter validation, and the difference between a demonstration and production security.
