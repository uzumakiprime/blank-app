import streamlit as st
#import joblib
import json
import numpy as np
import lightgbm as lgb
# --------------------------------------------------
# PAGE CONFIG
# --------------------------------------------------

st.set_page_config(
    page_title="APK Malware Detector",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ APK Malware Detector")
st.write("Upload a JSON record from the APK EMBER dataset")

# --------------------------------------------------
# FEATURE EXTRACTION
# --------------------------------------------------

def extract_features(record):

    features = []

    # Histogram (256)
    features.extend(record["histogram"])

    # Byte Entropy (256)
    features.extend(record["byteentropy"])

    # Strings
    strings = record["strings"]

    features.append(strings["numstrings"])
    features.append(strings["avlength"])
    features.append(strings["printables"])
    features.append(strings["entropy"])

    features.extend(strings["printabledist"])

    string_counts = strings.get("string_counts", {})

    features.append(string_counts.get("command", 0))
    features.append(string_counts.get("create", 0))
    features.append(string_counts.get("file", 0))
    features.append(string_counts.get("http://", 0))
    features.append(string_counts.get("ipv6_addr", 0))
    features.append(string_counts.get("resource", 0))
    features.append(string_counts.get("url", 0))
    features.append(string_counts.get("window", 0))

    # General
    general = record["general"]

    features.append(general["size"])
    features.append(general["entropy"])
    features.append(general["is_pe"])

    start_bytes = general.get("start_bytes", [0, 0, 0, 0])

    while len(start_bytes) < 4:
        start_bytes.append(0)

    features.extend(start_bytes[:4])

    return np.array(features, dtype=np.float32)

# --------------------------------------------------
# LOAD MODEL
# --------------------------------------------------

#@st.cache_resource
#def load_model():
#    return joblib.load("apk_ember_lgbm.pkl")

@st.cache_resource
def load_model():
    return lgb.Booster(model_file="EMBER2024_apk.model")

model = load_model()

# --------------------------------------------------
# FILE UPLOAD
# --------------------------------------------------

uploaded_file = st.file_uploader(
    "Upload JSON File",
    type=["json", "jsonl"]
)

# --------------------------------------------------
# PREDICTION
# --------------------------------------------------

if uploaded_file is not None:

    try:

        content = uploaded_file.read().decode("utf-8")

        # Handle JSONL
        first_line = content.strip().split("\n")[0]

        record = json.loads(first_line)

        x = extract_features(record).reshape(1, -1)

        pred_prob = float(model.predict(x)[0])

        prediction = 1 if pred_prob >= 0.5 else 0

        confidence = pred_prob if prediction == 1 else (1 - pred_prob)

        st.subheader("Prediction Result")

        if prediction == 1:
            st.error(
                f"🚨 Malware Detected\n\nConfidence: {confidence:.2%}"
            )
        else:
            st.success(
                f"✅ Benign File\n\nConfidence: {confidence:.2%}"
            )

        st.write("---")

        st.write("### File Information")

        st.write("SHA256:", record.get("sha256", "N/A"))
        st.write("MD5:", record.get("md5", "N/A"))
        st.write("File Type:", record.get("file_type", "N/A"))

        if "general" in record:
            st.write(
                "Size:",
                record["general"].get("size", "N/A")
            )

    except Exception as e:
        st.error(f"Error: {str(e)}")
