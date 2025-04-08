# Intrusion Detection Datasets

## CICIDS-2017 Dataset

**Kaggle Link:** [https://www.kaggle.com/datasets/bertvankeulen/cicids-2017](https://www.kaggle.com/datasets/bertvankeulen/cicids-2017)  
**Description:** Network flow data processed using CICFlowMeter. Includes 80 features and is categorized into 1 benign and 15 attack types.  
**Credits:** Canadian Institute for Cybersecurity (CIC)  
**Reference:**  
Sharafaldin I., Lashkari A.H., and Ghorbani A.A.  
*Toward generating a new intrusion detection dataset and intrusion traffic characterization*,  
Proceedings of the 4th International Conference on Information Systems Security and Privacy ICISSP - Volume 1, 108-116, 2018.

---

## CSE-CIC-IDS2018 Dataset

**Kaggle Link:** [https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv](https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv)  
**Description:** Logs from the University of New Brunswick's servers, focusing on DDoS attacks. Contains 80 columns of IDS logging data.  

**Get the Full Dataset:** [https://www.unb.ca/cic/datasets/ids-2018.html](https://www.unb.ca/cic/datasets/ids-2018.html)

**Download Command:**
```bash
aws s3 sync --no-sign-request --region <your-region> "s3://cse-cic-ids2018/" dest-dir
```

**Reference:**  
Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani,  
“Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization”,  
4th International Conference on Information Systems Security and Privacy (ICISSP), Portugal, January 2018.

---

## KDD Cup 1999 Dataset

**UCI Link:** [http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html](http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html)  
**Description:** A classic dataset used for intrusion detection tasks. It includes labeled network traffic data, with training data (`kddcup.data.gz`), test data with corrected labels (`corrected.gz`), and feature descriptions (`kddcup.names`).

### Key Files:
- `kddcup.data.gz`: The full training dataset (compressed).
- `corrected.gz`: Test data with corrected labels (compressed).
- `kddcup.names`: A list of features and their descriptions.

**Credits:** UCI Machine Learning Repository  
**Reference:**  
Third International Knowledge Discovery and Data Mining Tools Competition, held alongside KDD-99.
