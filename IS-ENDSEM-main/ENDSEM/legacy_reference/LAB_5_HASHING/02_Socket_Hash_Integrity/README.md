# Socket hash integrity

## What it does

Client/server integrity verification using a returned digest.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/server.py`
- `modifications/02_server.py`

## Reusable blocks

Input/encoding -> core Socket hash integrity operation -> inverse/verification -> output.

## Know before modifying

Understand Sender and receiver hash the same bytes and compare digests, representation conversions, parameter validation, and the difference between a demonstration and production security.
