#!/bin/bash

declare -x PROJ_PATH=$(dirname $(dirname $(realpath $0)))
rm -rvf $(find ${PROJ_PATH} -name '__pycache__' | xargs)
rm -rvf ${PROJ_PATH}/bin/{Activate.ps1,activate,activate.csh,activate.fish,pip,pip3,pip3.12,python,python3,python3.12}
rm -rvf ${PROJ_PATH}/{include,lib,lib64,pyvenv.cfg}

