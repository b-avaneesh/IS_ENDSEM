# DES/AES performance comparison

## What it does

Measure encryption/decryption time for syllabus algorithms.

## Baseline and source status

- `00_original/SOURCE_STATUS.md` records that no official source listing appeared in the manuals.
- `00_original/generated_baseline.py` is runnable code derived from the official exercise and clearly labeled as an addition.
- The unchanged manuals are preserved in `SOURCE_MATERIAL/`.

## Modified versions (additions)

- `modifications/02_benchmark.py`
- `modifications/benchmark.py`

## Reusable blocks

Input/encoding -> core DES/AES performance comparison operation -> inverse/verification -> output.

## Know before modifying

Understand Use identical workloads and perf_counter, representation conversions, parameter validation, and the difference between a demonstration and production security.
