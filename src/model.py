import numpy as np
from sklearn.ensemble import IsolationForest
from tensorflow.keras import layers, models

class AutoencoderModel:
    def __init__(self, input_dim):
        inp = layers.Input(shape=(input_dim,))
        enc = layers.Dense(64, activation="relu")(inp)
        enc = layers.Dense(32, activation="relu")(enc)
        dec = layers.Dense(64, activation="relu")(enc)
        out = layers.Dense(input_dim, activation="linear")(dec)
        self.model = models.Model(inp, out)
        self.model.compile(optimizer="adam", loss="mse")

    def train(self, X, epochs=5, batch_size=128):
        self.model.fit(X, X, epochs=epochs, batch_size=batch_size, verbose=0)

    def score(self, X):
        recon = self.model.predict(X, verbose=0)
        return ((X - recon)**2).mean(axis=1)

class IsolationForestModel:
    def __init__(self):
        self.model = IsolationForest(contamination=0.01, random_state=42)

    def train(self, X):
        self.model.fit(X)

    def score(self, X):
        return -self.model.decision_function(X)
