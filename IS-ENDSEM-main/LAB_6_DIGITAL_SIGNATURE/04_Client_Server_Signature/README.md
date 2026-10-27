# Client/server signatures

## What it does

Send a signed message and verify it at a server.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/client.py`
- `modifications/server.py`

## Reusable blocks

Input/encoding -> core Client/server signatures operation -> inverse/verification -> output.

## Know before modifying

Understand send message + public key + signature; verify before accepting, representation conversions, parameter validation, and the difference between a demonstration and production security.
