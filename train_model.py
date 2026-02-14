import pandas as pd
import joblib
import os
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier

# --- ADD THIS PRINT TO SEE IF IT STARTS ---
print("🚀 [1/3] Script started! Loading data...")

cols = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent',
    'hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login',
    'count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate',
    'dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty'
]

if not os.path.exists("KDDTrain+.txt"):
    print("❌ ERROR: 'KDDTrain+.txt' is missing from this folder!")
else:
    train_df = pd.read_csv("KDDTrain+.txt", names=cols)
    train_df["attack"] = (train_df["label"] != "normal").astype(int)
    X = train_df.drop(["label", "difficulty", "attack"], axis=1)
    y = train_df["attack"]

    preprocess = ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown="ignore"), cat_cols := ["protocol_type", "service", "flag"]),
        ("num", "passthrough", [c for c in X.columns if c not in cat_cols])
    ])

    pipeline = Pipeline([
        ("preprocess", preprocess),
        ("model", RandomForestClassifier(n_estimators=100, random_state=42))
    ])

    print("🧠 [2/3] Training model... This takes 1-2 minutes. Please wait.")
    pipeline.fit(X, y)

    joblib.dump(pipeline, "intrusion_pipeline.pkl")
    print("✅ [3/3] SUCCESS: intrusion_pipeline.pkl created!")