# RSA digital signature

## What it does

Generate, sign, and verify using RSA and SHA-256.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/02_rsa_signature.py`
- `modifications/rsa_signature.py`

## Reusable blocks

Input/encoding -> core RSA digital signature operation -> inverse/verification -> output.

## Know before modifying

Understand signature = RSA-PSS(private, SHA-256(message)), representation conversions, parameter validation, and the difference between a demonstration and production security.
