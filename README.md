# UNSW-NB15 Network Traffic Analysis Dashboard

[](https://www.python.org/downloads/)
[](https://streamlit.io)
[](https://altair-viz.github.io/)
[](https://opensource.org/licenses/MIT)

An interactive web dashboard for visualizing and analyzing the **UNSW-NB15 dataset**. This project provides deep insights into network traffic patterns, helping to distinguish between normal and malicious activities and to understand the characteristics of various cyber-attacks.

The dashboard is built with **Streamlit** and **Altair**.

This project was developed for the Data Visualization (Visualización de Datos) course, part of the Master's Degree in Data Science & Engineering at UNED.




## Key Features

![](./demo/Demo.gif)

The dashboard is organized into four main tabs, each providing a unique perspective on the data:

  - **General Traffic Overview**: Get a high-level summary of the network activity.

      - Daily connection counts (Normal vs. Malicious).
      - Proportional view of traffic types.
      - Top 10 most frequent attack categories.
      - Analysis of the most used protocols, services, and most active source/destination IPs, with options to filter by traffic type.

  - **Malicious Traffic Composition**: Dive deep into the anatomy of specific attacks.

      - Select an attack type (e.g., `DoS`, `Exploits`, `Fuzzers`) from a dropdown menu.
      - Visualize the distribution of protocols, services, connection states, and port usage for the selected attack.

  - **Network Performance Impact**: Analyze how malicious activities affect network performance.

      - Compare the distribution of bytes sent (`sbytes`) and received (`dbytes`) for normal and malicious traffic.
      - Visualize the relationship between connection duration (`dur`) and the number of packets sent/received.

  - **Impact of Each Attack Type**: Understand the specific network footprint of each attack category.

      - Identify the top source and destination IPs involved in malicious activities.
      - Compare the average volume of packets sent (`Spkts`) and received (`Dpkts`) across different attack types.
      - Analyze source (`sloss`) and destination (`dloss`) packet loss rates for each attack.



## Technology Stack

  - **Language**: Python
  - **Dashboard**: Streamlit
  - **Data Visualization**: Altair
  - **Data Manipulation**: Pandas
  - **Development Environment**: Jupyter Notebook (`Practica.ipynb` contains the initial exploratory data analysis).



## Dataset

This project uses the **UNSW-NB15 dataset**, a comprehensive collection of real normal network traffic and synthesized contemporary attack behaviors.

**Important**: Due to its large size, the dataset files are **not included** in this repository. You must download them from the official source and place them in the `CSV Files/` directory.

  - [**Download the UNSW-NB15 Dataset Here**](https://research.unsw.edu.au/projects/unsw-nb15-dataset)

You will need the following files from the dataset:

  - `UNSW-NB15_1.csv`
  - `UNSW-NB15_2.csv`
  - `UNSW-NB15_3.csv`
  - `UNSW-NB15_4.csv`
  - `NUSW-NB15_features.csv`



## Getting Started

Follow these instructions to set up and run the project locally.

### Prerequisites

  - Python 3.10 or higher
  - Git

### Installation & Setup

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/Ubikitina/data-visualization.git
    cd data-visualization
    ```

2.  **Create and activate a virtual environment** (recommended):

    ```bash
    # For Windows
    python -m venv venv
    .\venv\Scripts\activate

    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the required dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Download and place the dataset:**

      - Download the dataset from the link provided above.
      - Unzip the file and move the required `.csv` files into the `CSV Files/` directory in the project's root.

### Running the Application

Once the setup is complete, you can run the Streamlit dashboard with the following command:

```bash
streamlit run dashboard.py
```

Your web browser should automatically open a new tab with the running application.


## Project Structure

```
data-visualization/
│
├── .gitignore
├── dashboard.py                # The main Streamlit application script
├── Practica.ipynb              # Jupyter Notebook for EDA
├── README.md                   # This README file.
├── requirements.txt            # Python dependencies
│
├── CSV Files/                  # (Place dataset CSVs here)
│   └── The UNSW-NB15 description.pdf
│
├── demo/                       # Animated GIF showcasing the dashboard
│   └── Demo.gif
│
├── doc/                        # All project documentation.
│   ├── Memoria_Proyecto_Visualizacion_Datos.pdf  # Main project report 
│   └── Objetivos_Proyecto.pdf                    # Project's objectives
│
└── streamlit/                  # Streamlit configuration file
    └── config.toml
```


## Contributing

Contributions are welcome! If you have any suggestions for improvements or find any issues, please feel free to open an issue or submit a pull request.


## License

This project is released under the terms of the **MIT License**.

The purpose of this license is to allow the free reuse of the code for any purpose, provided that the original copyright notice and the license text are included in any copy or substantial portion of the software. This means that while you can use, modify, and distribute this code, **you have a legal obligation to provide original authorship attribution**.

You can find a complete copy of the license text in the `LICENSE` file in this repository.


## Warning on Academic Integrity and Plagiarism

This repository and its contents are published for a dual purpose:

1.  **Educational:** As reference and consultation material for other developers interested in the topics covered.
2.  **Professional:** As part of my personal portfolio to demonstrate my skills and the projects I have worked on.


**⚠️ IMPROPER USE AND CONSEQUENCES:**

The use, copy, or adaptation, in whole or in part, of this work to be submitted as one's own in any course, subject, or academic context—whether at UNED or any other educational institution—constitutes **plagiarism**.

Plagiarism is a **serious offense** against academic integrity, punishable under Universities Academic Disciplinary Regulations and other similar rules. The plagiarism detection tools used by the universities compare student submissions against billions of internet sources, including public GitHub repositories, so any copy will be detected.

By publishing this work under a license that requires attribution, this repository promotes good faith and ethical use of the code. Anyone who ignores the terms of the license and academic regulations to commit fraud does so at their own sole and exclusive risk.