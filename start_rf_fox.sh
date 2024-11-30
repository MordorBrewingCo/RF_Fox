#!/bin/bash

# Set variables
REPO_DIR="$HOME/PycharmProjects/pythonProject/hermesrf"
VENV_DIR="$REPO_DIR/myenv"
FLDIGI_SCREEN_NAME="fldigi"
RF_FOX_SCREEN_NAME="rf_fox"

# Start fldigi in headless mode using xvfb and screen
echo "Starting fldigi in headless mode..."
screen -dmS $FLDIGI_SCREEN_NAME xvfb-run fldigi
if [ $? -eq 0 ]; then
    echo "fldigi started successfully in a detached screen session named '$FLDIGI_SCREEN_NAME'."
else
    echo "Failed to start fldigi. Please ensure fldigi is installed and configured properly."
    exit 1
fi

# Activate the Python virtual environment and start RF_fox
echo "Activating Python virtual environment and starting RF_fox..."
cd $REPO_DIR || { echo "Failed to change directory to $REPO_DIR. Exiting."; exit 1; }

if [ -f "$VENV_DIR/bin/activate" ]; then
    screen -dmS $RF_FOX_SCREEN_NAME bash -c "source $VENV_DIR/bin/activate && python3 RF_fox.py"
    if [ $? -eq 0 ]; then
        echo "RF_fox started successfully in a detached screen session named '$RF_FOX_SCREEN_NAME'."
    else
        echo "Failed to start RF_fox. Please ensure your virtual environment and Python script are set up correctly."
        exit 1
    fi
else
    echo "Virtual environment not found at $VENV_DIR. Please ensure the path is correct."
    exit 1
fi

echo "All processes started successfully. Use 'screen -list' to view active screen sessions."
