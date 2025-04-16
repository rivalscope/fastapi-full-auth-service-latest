#!/bin/bash
# Run all pytest tests in the tests directory with correct PYTHONPATH

PYTHONPATH=$(dirname "$0")/.. pytest tests/ "$@"
