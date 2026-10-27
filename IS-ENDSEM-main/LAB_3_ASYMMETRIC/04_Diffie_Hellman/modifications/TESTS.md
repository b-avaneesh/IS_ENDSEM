# Test cases

## Test 1 - normal case

Run the program with a short valid message and the displayed/default valid parameters. Expected: inverse/verification recovers or accepts the original data.

## Test 2 - edge or tamper case

Use an empty message, invalid key, or change one byte before verification as applicable. Expected: clean empty handling, a validation error, or verification failure.

Status: covered by `tests/smoke_test.py` when that program has an automated assertion; otherwise documented for manual execution because it is interactive, timing-based, or client/server based.
