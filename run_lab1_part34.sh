#!/bin/bash

# Package name
PACKAGE="pwntools"

# Check if the package is installed
if ! pip3 list | grep -q "^$PACKAGE "; then
    echo "Package $PACKAGE is not installed. Installing now..."
    pip3 install $PACKAGE
fi

LAB1="./lab1_autograder.py"
if [ ! -f "$LAB1" ]; then
    wget https://raw.githubusercontent.com/UCR-CS153-Summer-2024/UCR-CS153-Summer-2024.github.io/main/lab1_autograder.py
fi

python3 ./lab1_autograder.py
