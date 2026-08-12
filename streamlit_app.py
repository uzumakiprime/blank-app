import streamlit as st
import joblib

st.set_page_config(
    page_title="APK Malware Detector",
    page_icon="🛡️"
)

st.title("🛡️ APK Malware Detector")

try:
    model = joblib.load("apk_ember_lgbm.pkl")

    st.success("Model loaded successfully!")

    st.write("Model Type:")
    st.code(str(type(model)))

except Exception as e:
    st.error(f"Error loading model: {e}")
