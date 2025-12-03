import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(
    page_title="Network Traffic Classifier",
    page_icon="🔍",
    layout="wide"
)

st.markdown("""
    <style>
        /* Sidebar Styling */
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #0f172a 0%, #1e293b 100%);
            color: white;
            padding-top: 2rem;
        }
        [data-testid="stSidebar"] h1, 
        [data-testid="stSidebar"] h2, 
        [data-testid="stSidebar"] h3, 
        [data-testid="stSidebar"] p, 
        [data-testid="stSidebar"] label {
            color: #f1f5f9 !important;
        }
        /* Cards */
        .card {
            background-color: #ffffff10;
            backdrop-filter: blur(12px);
            border-radius: 15px;
            padding: 1rem 1.5rem;
            margin-bottom: 1rem;
            border: 1px solid rgba(255,255,255,0.1);
        }
        /* Metric and Section Headers */
        h2, h3 {
        }
        /* Footer */
        footer {
            visibility: hidden;
        }
    </style>
""", unsafe_allow_html=True)


st.sidebar.image("https://cdn-icons-png.flaticon.com/512/18250/18250974.png", width=160)
st.sidebar.markdown("## 🧠 Network Classifier")
st.sidebar.markdown(
    "Select a trained model and input data to classify network traffic.\n\n"
    "📂 Upload a CSV file or manually enter values."
)

st.sidebar.markdown("---")
st.sidebar.header("⚙️ Model Settings")

# Check available models
available_models = []
if os.path.exists("XGBoost.pkl"):
    available_models.append("XGBoost")
if os.path.exists("RandomForest.pkl"):
    available_models.append("RandomForest")

if not available_models:
    st.sidebar.error("⚠️ No trained models found!")
    st.stop()

selected_model = st.sidebar.selectbox(
    "Select Model",
    available_models,
    help="Choose which model to use for prediction"
)

# Load the selected model
@st.cache_resource
def load_model(model_name):
    return joblib.load(f"{model_name}.pkl")

model = load_model(selected_model)
st.sidebar.success(f"✅ {selected_model} loaded successfully!")

st.sidebar.markdown("---")
st.sidebar.caption("Developed by **SAN Systems** 🚀")


# Page configuration
st.set_page_config(
    page_title="Network Traffic Classifier",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 Network Traffic Classification")
st.markdown("Upload a CSV file or input features manually to classify network traffic")

# Feature names
FEATURES = ['Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
            'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
            'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
            'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
            'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
            'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot',
            'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
            'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
            'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
            'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s',
            'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean',
            'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt',
            'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
            'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg',
            'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
            'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
            'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
            'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
            'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts',
            'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
            'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']



# Main content - Input method selection
st.header("Input Data")
input_method = st.radio(
    "Select input method:",
    ["Upload CSV File", "Manual Input"],
    horizontal=True
)

input_data = None

if input_method == "Upload CSV File":
    st.markdown("Upload a CSV file containing exactly one row with all required features")
    
    uploaded_file = st.file_uploader(
        "Choose a CSV file",
        type=['csv'],
        help="CSV should contain one row with all 75 features"
    )
    
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            
            # Remove Label column if it exists
            if 'Label' in df.columns:
                st.info(f"True Label: **{df['Label'].values[0]}**")
                df = df.drop('Label', axis=1)
            
            # Validate columns
            if df.shape[0] != 1:
                st.error(f"❌ CSV should contain exactly 1 row, but contains {df.shape[0]} rows")
            elif list(df.columns) != FEATURES:
                st.error("❌ CSV columns don't match expected features")
                st.write("Expected features:", FEATURES)
                st.write("Found features:", list(df.columns))
            else:
                input_data = df
                st.success("✅ CSV file loaded successfully!")
                
                # Display the data
                st.subheader("Input Data Preview")
                st.dataframe(input_data)
                
        except Exception as e:
            st.error(f"Error reading CSV: {str(e)}")

else:  # Manual Input
    st.markdown("Enter values for all 75 features (you can use sample values for testing)")
    
    # Create input fields in columns
    col1, col2, col3 = st.columns(3)
    
    feature_values = {}
    
    for i, feature in enumerate(FEATURES):
        if i % 3 == 0:
            with col1:
                feature_values[feature] = st.number_input(
                    feature,
                    value=0.0,
                    format="%.6f",
                    key=feature
                )
        elif i % 3 == 1:
            with col2:
                feature_values[feature] = st.number_input(
                    feature,
                    value=0.0,
                    format="%.6f",
                    key=feature
                )
        else:
            with col3:
                feature_values[feature] = st.number_input(
                    feature,
                    value=0.0,
                    format="%.6f",
                    key=feature
                )
    
    if st.button("Use Manual Input"):
        input_data = pd.DataFrame([feature_values])
        st.success("✅ Manual input ready for prediction!")

# Prediction Section
if input_data is not None:
    st.header("🎯 Prediction Results")

    if st.button("🔮 Predict", type="primary", use_container_width=True):
        try:
            # Make prediction
            prediction = model.predict(input_data)[0]
            prediction_proba = model.predict_proba(input_data)[0]
            confidence = max(prediction_proba) * 100

            # Create columns for key metrics
            st.markdown("### 📊 Summary")
            metric_col1, metric_col2 = st.columns(2)
            with metric_col1:
                st.metric("Predicted Class", prediction)
            with metric_col2:
                st.metric("Confidence", f"{confidence:.2f}%")

            st.markdown("---")

            st.markdown("### 🔎 Visual Insights")
            vis1, vis2 = st.columns(2)

            with vis1:
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=confidence,
                    title={'text': "Prediction Confidence"},
                    gauge={
                        'axis': {'range': [0, 100]},
                        'bar': {'color': "#00C49F"},
                        'bgcolor': "white",
                        'borderwidth': 2,
                        'steps': [
                            {'range': [0, 50], 'color': "#FF8A80"},
                            {'range': [50, 80], 'color': "#FFD54F"},
                            {'range': [80, 100], 'color': "#A5D6A7"}
                        ]
                    }
                ))
                fig_gauge.update_layout(
                    height=300,
                    margin=dict(l=10, r=10, t=50, b=10),
                    paper_bgcolor="rgba(0,0,0,0)",
                    font=dict(size=16)
                )
                st.plotly_chart(fig_gauge, use_container_width=True)

            with vis2:
                proba_df = pd.DataFrame({
                    'Class': model.classes_,
                    'Probability': prediction_proba
                }).sort_values('Probability', ascending=False)

                fig_bar = px.bar(
                    proba_df,
                    x='Class',
                    y='Probability',
                    text='Probability',
                    color='Probability',
                    color_continuous_scale='Blues',
                    title="Probability Distribution"
                )
                fig_bar.update_traces(texttemplate='%{text:.2f}', textposition='outside')
                fig_bar.update_layout(
                    yaxis_range=[0, 1],
                    height=300,
                    margin=dict(l=10, r=10, t=50, b=10),
                    paper_bgcolor="rgba(0,0,0,0)"
                )
                st.plotly_chart(fig_bar, use_container_width=True)

            st.markdown("---")

            if hasattr(model, 'feature_importances_'):
                st.markdown("### 🧠 Top 10 Feature Importances")
                importances = model.feature_importances_
                feature_importance_df = pd.DataFrame({
                    'Feature': FEATURES,
                    'Importance': importances
                }).sort_values('Importance', ascending=False).head(10)

                fig_imp = px.bar(
                    feature_importance_df,
                    x='Importance',
                    y='Feature',
                    orientation='h',
                    color='Importance',
                    color_continuous_scale='Viridis',
                    title="Most Influential Features"
                )
                fig_imp.update_layout(
                    height=400,
                    margin=dict(l=10, r=10, t=50, b=10),
                    paper_bgcolor="rgba(0,0,0,0)"
                )
                st.plotly_chart(fig_imp, use_container_width=True)

            # Display probability table in expandable container
            with st.expander("📋 Show Class Probabilities Table"):
                st.dataframe(proba_df, use_container_width=True)

        except Exception as e:
            st.error(f"Error during prediction: {str(e)}")


# Footer
st.markdown("---")
st.markdown("**Note:** Ensure your input data matches the training data distribution for accurate predictions.")