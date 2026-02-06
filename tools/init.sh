#!/bin/bash

declare -x PROJ_PATH=$(dirname $(dirname $(realpath $0)))
python -m venv .

