# cicids_2017_glow_model.py

import os
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    accuracy_score,
    f1_score,
)
import matplotlib.pyplot as plt


# Glow-based Model
class GlowBlock(nn.Module):
    def __init__(self, input_dim, hidden_dim):
        super(GlowBlock, self).__init__()
        self.actnorm = nn.BatchNorm1d(input_dim)
        self.linear1 = nn.Linear(input_dim, hidden_dim)
        self.relu = nn.ReLU()
        self.linear2 = nn.Linear(hidden_dim, input_dim)

    def forward(self, x):
        x = self.actnorm(x)
        z = self.relu(self.linear1(x))
        z = self.linear2(z)
        return z


class GlowModel(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_blocks):
        super(GlowModel, self).__init__()
        self.blocks = nn.ModuleList(
            [GlowBlock(input_dim, hidden_dim) for _ in range(num_blocks)]
        )
        self.output_layer = nn.Linear(input_dim, 1)  # Output layer for binary classification

    def forward(self, x):
        for block in self.blocks:
            x = block(x)
        x = self.output_layer(x)  # Apply the final layer
        return x


# Train Function
def train_glow_model(model, train_loader, optimizer, criterion, epochs, device):
    model.train()
    for epoch in range(epochs):
        total_loss = 0
        for x, y in train_loader:
            x, y = x.to(device), y.to(device)
            optimizer.zero_grad()
            outputs = model(x)
            loss = criterion(outputs, y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        print(f"Epoch {epoch + 1}/{epochs}, Loss: {total_loss:.4f}")


# Evaluation Function
def evaluate_glow_model(model, test_loader, device):
    model.eval()
    all_outputs = []
    all_labels = []
    with torch.no_grad():
        for x, y in test_loader:
            x, y = x.to(device), y.to(device)
            outputs = model(x)
            all_outputs.append(outputs.cpu().numpy())
            all_labels.append(y.cpu().numpy())
    return np.concatenate(all_outputs), np.concatenate(all_labels)


# IP Address Conversion
def ip_to_int(ip):
    try:
        octets = str(ip).split(".")
        if len(octets) == 4:  # Ensure it is a valid IPv4 address
            return sum([int(octet) * (256 ** (3 - i)) for i, octet in enumerate(octets)])
    except:
        return 0  # Handle invalid IPs by returning 0 (or any other default value)
    return 0


# Main Function
if __name__ == "__main__":
    # Configuration
    input_dim = 4  # Features: src_ip, dest_ip, src_port, dest_port
    hidden_dim = 64
    num_blocks = 8
    epochs = 10
    batch_size = 128
    learning_rate = 1e-3

    # Load Dataset
    dataset_path = "/content/cicids-2017/combined_dataset.csv"
    dataset = pd.read_csv(dataset_path)

    # Extract Relevant Features
    dataset = dataset[["Src IP dec", "Src Port", "Dst IP dec", "Dst Port", "Label"]]
    dataset = dataset.dropna()

    # Encode Labels (1 for benign, 0 for other attacks)
    dataset["Label"] = dataset["Label"].apply(lambda x: 1 if x.lower() == "benign" else 0)

    # Normalize Numerical Features
    numeric_cols = ["Src IP dec", "Dst IP dec"]
    dataset[numeric_cols] = (dataset[numeric_cols] - dataset[numeric_cols].min()) / (
        dataset[numeric_cols].max() - dataset[numeric_cols].min()
    )

    # Convert IPs to integers if "Src IP" and "Dst IP" exist
    if "Src IP" in dataset.columns and "Dst IP" in dataset.columns:
        dataset["Src IP dec"] = dataset["Src IP"].apply(ip_to_int)
        dataset["Dst IP dec"] = dataset["Dst IP"].apply(ip_to_int)
    else:
        print("Error: 'Src IP' or 'Dst IP' column is missing!")

    # Update columns list based on actual names
    cols_to_process = ["Src IP dec", "Dst IP dec", "Src Port", "Dst Port"]
    existing_cols = [col for col in cols_to_process if col in dataset.columns]

    # Process only existing columns
    if existing_cols:
        dataset[existing_cols] = dataset[existing_cols].apply(pd.to_numeric, errors="coerce")
    else:
        print("Error: None of the expected columns are present!")

    # Drop rows with missing values
    dataset.dropna(inplace=True)

    # Extract features and labels
    if all(col in dataset.columns for col in cols_to_process):
        features = dataset[cols_to_process].values
        labels = dataset["Label"].values
    else:
        print("Error: Missing columns for features extraction.")

    # Train-Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.8, random_state=84, stratify=labels
    )

    # Convert to Tensors
    X_train_tensor = torch.tensor(X_train, dtype=torch.float32)
    y_train_tensor = torch.tensor(y_train, dtype=torch.float32).unsqueeze(1)
    X_test_tensor = torch.tensor(X_test, dtype=torch.float32)
    y_test_tensor = torch.tensor(y_test, dtype=torch.float32).unsqueeze(1)

    # Data Loaders
    train_dataset = TensorDataset(X_train_tensor, y_train_tensor)
    test_dataset = TensorDataset(X_test_tensor, y_test_tensor)
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

    # Device Setup
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # Initialize Glow Model
    glow_model = GlowModel(input_dim=input_dim, hidden_dim=hidden_dim, num_blocks=num_blocks).to(device)
    optimizer = optim.Adam(glow_model.parameters(), lr=learning_rate)
    criterion = nn.BCEWithLogitsLoss()

    # Train the Model
    print("Training Glow Model...")
    train_glow_model(glow_model, train_loader, optimizer, criterion, epochs, device)

    # Evaluate the Model
    print("Evaluating Glow Model...")
    outputs, labels = evaluate_glow_model(glow_model, test_loader, device)

    from sklearn.metrics import accuracy_score, f1_score, confusion_matrix

    # Classification Metrics
    predictions = (torch.sigmoid(torch.tensor(outputs)) > 0.5).int().cpu().numpy()

    # Ensure labels are already NumPy arrays
    if not isinstance(labels, np.ndarray):
        labels = np.array(labels)

    # Calculate metrics
    accuracy = accuracy_score(labels, predictions)
    f1 = f1_score(labels, predictions)

    # False Discovery Rate (FDR)
    cm = confusion_matrix(labels, predictions)
    false_discovery_rate = 1 - (cm[1, 1] / (cm[1, 1] + cm[0, 1]))

    print(f"Accuracy: {accuracy * 100:.2f}%")
    print(f"F1 Score: {f1:.2f}")
    print(f"False Discovery Rate (FDR): {false_discovery_rate:.2f}")

    # Confusion Matrix
    cm = confusion_matrix(labels, predictions)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Attack", "Benign"])
    disp.plot(cmap="viridis")
    plt.title("Confusion Matrix")
    plt.show()