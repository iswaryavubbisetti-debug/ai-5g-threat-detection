import streamlit as st
import pandas as pd
import numpy as np
import json
from sklearn.preprocessing import StandardScaler

from src.model import AutoencoderModel, IsolationForestModel
from src.response import automated_response

st.title("🔐 AI Threat Detection in Cloud-Native 5G")

st.sidebar.header("⚙️ Choose Model")
model_choice = st.sidebar.selectbox("Model", ["Autoencoder", "Isolation Forest"])

uploaded_file = st.file_uploader("📂 Upload Network Flow CSV", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.write("📊 Uploaded Data Sample", df.head())

    scaler = StandardScaler()
    X = scaler.fit_transform(df.select_dtypes(include=[np.number]))

    if model_choice == "Autoencoder":
        model = AutoencoderModel(input_dim=X.shape[1])
        model.train(X)
        scores = model.score(X)
    else:
        model = IsolationForestModel()
        model.train(X)
        scores = model.score(X)

    threshold = np.percentile(scores, 95)
    anomalies = (scores >= threshold).astype(int)
    df["anomaly"] = anomalies

    st.subheader("🚨 Detection Summary")
    st.write(df["anomaly"].value_counts())

    alerts = [{"type": "ddos", "src_ip": "192.168.0.1"} for _ in range(df["anomaly"].sum())]
    with open("alerts.json", "w") as f:
        json.dump(alerts, f)

    st.download_button("⬇️ Download Alerts JSON", json.dumps(alerts), "alerts.json")

    if st.button("⚡ Trigger Automated Response"):
        automated_response("alerts.json")
        st.success("Automated Response Executed ✅")
