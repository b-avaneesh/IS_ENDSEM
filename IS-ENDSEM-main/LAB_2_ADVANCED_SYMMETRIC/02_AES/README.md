# AES

## What it does

Encrypt/decrypt with AES-128/192/256.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/00_aes.py`
- `modifications/02_hex_input_output.py`

## Reusable blocks

Input/encoding -> core AES operation -> inverse/verification -> output.

## Know before modifying

Understand 128-bit blocks; SubBytes, ShiftRows, MixColumns, AddRoundKey, representation conversions, parameter validation, and the difference between a demonstration and production security.
