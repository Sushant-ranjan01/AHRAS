Hii this project is still underprocess 

# Running the Project

## Start Main Security Pipeline

Run:

python main_pipeline.py

## Start Dashboard Server

Run:

uvicorn dashboard.dashboard_server:app --reload

Open dashboard in browser:

http://127.0.0.1:8000/dashboard


# Installation

## Create Virtual Environment

python -m venv venv

## Activate Virtual Environment

### Windows

venv\Scripts\activate

### Linux/Mac

source venv/bin/activate

## Install Dependencies

pip install -r requirements.txt

# Dataset Setup

The ML datasets are not included in this repository because GitHub has file size limitations.

## Required Datasets

Place the following datasets inside:

ml_engine/datasets/raw/

Required files:

- Benign-Monday-no-metadata.parquet
- DDoS-Friday-no-metadata.parquet
- WebAttacks-Thursday-no-metadata.parquet

## Generate Processed Dataset

Run:

python ml_engine/preprocess_dataset.py

This will generate:

- final_dataset.csv
- final_features.csv
- runtime_features.csv

inside:

ml_engine/datasets/processed/

## Train Model

Run:

python ml_engine/train_model.py

Generated models will be stored in:

ml_engine/models/

## Notes

- Raw and processed datasets are excluded using `.gitignore`
- Large datasets are not pushed to GitHub due to GitHub file size limits
