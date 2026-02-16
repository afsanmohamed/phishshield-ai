import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle

# Dataset with 7 features
data = {
    "url_length": [50,180,25,210,45,160,90,200,30,170],
    "has_at":     [0,1,0,1,0,0,0,1,0,1],
    "has_https":  [1,0,1,0,1,0,1,0,1,0],
    "has_hyphen": [0,1,0,1,0,1,0,1,0,1],
    "dot_count":  [2,5,1,6,2,4,3,5,1,6],
    "has_words":  [0,1,0,1,0,1,0,1,0,1],
    "is_http":    [0,1,0,1,0,1,0,1,0,1],
    "label":      [0,1,0,1,0,1,0,1,0,1]
}

df = pd.DataFrame(data)

X = df.drop("label", axis=1)
y = df["label"]

model = RandomForestClassifier()
model.fit(X, y)

# Save new model (OVERWRITES old one)
pickle.dump(model, open("phishing_model.pkl", "wb"))

print("✅ Model trained with 7 features & saved!")