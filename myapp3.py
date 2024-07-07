import pandas as pd
import streamlit as st
from joblib import load
import numpy as np
import random
from datetime import datetime
import sqlite3
import hashlib
from fpdf import FPDF
import tempfile
import os

# Load the model
model = load('random_forest_model.joblib')

# Set up SQLite database
conn = sqlite3.connect('user_credentials.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
conn.commit()

# Load the existing dataset
existing_dataset_path = 'C:/Users/Yash Bhandare/.vscode/python/new19may/data.csv'

# Ensure the path is correct and check permissions
if not os.path.exists(existing_dataset_path):
    st.error("The dataset path does not exist. Please check the path and try again.")
else:
    try:
        existing_dataset = pd.read_csv(existing_dataset_path)
    except PermissionError as e:
        st.error(f"Permission error: {e}")
    except Exception as e:
        st.error(f"An error occurred while loading the dataset: {e}")

# Set starting Patient ID
starting_patient_id = 20000

# Fake Indian names for referred by (with prefix 'Dr') and lab
doctors = ["Dr. Gupta", "Dr. Singh", "Dr. Patel", "Dr. Kumar", "Dr. Shah", "Dr. Joshi", "Dr. Rao", "Dr. Mishra", "Dr. Reddy", "Dr. Sharma"]
labs = ["Indian Diagnostic Centre", "Sai Labs", "Ganesh Pathology Lab", "Indian Health Lab", "Mahajan Diagnostics", "Jain Lab Services", "Shree Path Lab", "Nirvana Diagnostics"]

# Function to predict diabetes class
def predict_diabetes_class(age, bmi, fbg, postprandial_glucose, hba1c, urine_microalbumin, urine_glucose, urine_ketones, lipid_profile, systolic_bp, diastolic_bp):
    user_input = [age, bmi, fbg, postprandial_glucose, hba1c, urine_microalbumin, urine_glucose, urine_ketones, lipid_profile, systolic_bp, diastolic_bp]
    prediction = model.predict([user_input])
    if prediction == 2:
        return "Non-Diabetic"
    elif prediction == 1:
        return "Prediabetic"
    elif prediction == 0:
        return "Diabetic"
    else:
        return "Unknown"

# Function to generate fake values for additional columns
def generate_fake_values():
    global starting_patient_id
    patient_id = str(starting_patient_id)
    starting_patient_id += 1
    date = datetime.now().strftime("%Y-%m-%d")
    referred_by = random.choice(doctors)
    lab = random.choice(labs)
    return patient_id, date, referred_by, lab

# Function to register admin
def register_admin(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, 'admin'))
    conn.commit()

# Function to register user
def register_user(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, 'user'))
    conn.commit()

# Function to check if user exists and verify credentials
def authenticate_user(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_password))
    user = c.fetchone()
    return user

# Function to fetch all user credentials
def fetch_user_credentials():
    c.execute("SELECT username, role FROM users")
    users = c.fetchall()
    return users

# Function to generate PDF report
def generate_pdf_report(patient_id, name, gender, age, bmi, fbg, postprandial_glucose, hba1c, family_history, urine_microalbumin, urine_glucose, urine_ketones, lipid_profile, physical_activity, date, referred_by, lab, systolic_bp, diastolic_bp, prediction_result):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="Patient Report", ln=True, align='C')
    pdf.ln(10)

    pdf.cell(200, 10, txt="Patient Details:", ln=True)
    pdf.cell(200, 10, txt=f"Patient ID: {patient_id}", ln=True)
    pdf.cell(200, 10, txt=f"Name: {name}", ln=True)
    pdf.cell(200, 10, txt=f"Gender: {'Male' if gender == 0 else 'Female'}", ln=True)
    pdf.cell(200, 10, txt=f"Age: {age}", ln=True)
   
    pdf.cell(200, 10, txt=f"BMI: {bmi}", ln=True)
    pdf.cell(200, 10, txt=f"FBG: {fbg}", ln=True)
    pdf.cell(200, 10, txt=f"2 Hour Postprandial Glucose: {postprandial_glucose}", ln=True)
    pdf.cell(200, 10, txt=f"HbA1c: {hba1c}", ln=True)
    pdf.cell(200, 10, txt=f"Family History: {'Yes' if family_history == 1 else 'No'}", ln=True)
    pdf.cell(200, 10, txt=f"Urine Microalbumin: {urine_microalbumin}", ln=True)
    pdf.cell(200, 10, txt=f"Urine Glucose: {'Normal' if urine_glucose == 0 else 'Abnormal'}", ln=True)
    pdf.cell(200, 10, txt=f"Urine Ketones: {'Normal' if urine_ketones == 0 else 'Abnormal'}", ln=True)
    pdf.cell(200, 10, txt=f"Lipid Profile: {'Normal' if lipid_profile == 0 else 'Abnormal'}", ln=True)
    pdf.cell(200, 10, txt=f"Physical Activity: {physical_activity}", ln=True)
    pdf.cell(200, 10, txt=f"Date: {date}", ln=True)
    pdf.cell(200, 10, txt=f"Referred By: {referred_by}", ln=True)
    pdf.cell(200, 10, txt=f"Lab: {lab}", ln=True)
    pdf.cell(200, 10, txt=f"Systolic BP: {systolic_bp}", ln=True)
    pdf.cell(200, 10, txt=f"Diastolic BP: {diastolic_bp}", ln=True)

    pdf.ln(10)
    pdf.cell(200, 10, txt=f"Diabetes Prediction: {prediction_result}", ln=True)

    # Save PDF to a temporary file
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(temp_file.name)
    
    return temp_file.name

# Streamlit UI elements for input
st.title('Welcome to Diabetes Prediction System')

# Sidebar navigation
page = st.sidebar.selectbox("Navigation", ["Home", "Admin Dashboard"])

if page == "Home":
    st.subheader("User Login")
    username_input = st.text_input("Username")
    password_input = st.text_input("Password", type="password")

    if st.button("Login"):
        user = authenticate_user(username_input, password_input)
        if user:
            st.success(f"Welcome, {user[0]}! You are logged in as {user[2]}.")
            st.session_state['user'] = user
        else:
            st.error("Invalid username or password. Please try again.")

elif page == "Admin Dashboard":
    st.subheader("Admin Login")
    admin_username_input = st.text_input("Admin Username")
    admin_password_input = st.text_input("Admin Password", type="password")

    if st.button("Admin Login"):
        admin = authenticate_user(admin_username_input, admin_password_input)
        if admin and admin[2] == 'admin':
            st.success(f"Welcome, {admin[0]}! You are logged in as {admin[2]}.")
            st.session_state['admin'] = admin
        else:
            st.error("Invalid admin username or password. Please try again.")

    if 'admin' in st.session_state:
        st.subheader("Admin Dashboard")
        st.write("Here, you can view all user credentials.")

        users = fetch_user_credentials()
        if users:
            st.write("### User Credentials")
            for user in users:
                st.write(f"Username: {user[0]}, Role: {user[1]}")
        else:
            st.write("No user credentials found.")

# Streamlit UI elements for registration
st.sidebar.subheader("User Registration")
new_username = st.sidebar.text_input("New Username")
new_password = st.sidebar.text_input("New Password", type="password")
confirm_password = st.sidebar.text_input("Confirm Password", type="password")

if new_password == confirm_password and new_password != "":
    st.sidebar.info("Passwords match!")
    if st.sidebar.button("Register"):
        register_user(new_username, new_password)
        st.sidebar.success("Registration successful!")

# Streamlit UI elements for admin registration
st.sidebar.subheader("Admin Registration")
new_admin_username = st.sidebar.text_input("New Admin Username")
new_admin_password = st.sidebar.text_input("New Admin Password", type="password")
confirm_admin_password = st.sidebar.text_input("Confirm Admin Password", type="password")

if new_admin_password == confirm_admin_password and new_admin_password != "":
    st.sidebar.info("Admin passwords match!")
    if st.sidebar.button("Register Admin"):
        register_admin(new_admin_username, new_admin_password)
        st.sidebar.success("Admin registration successful!")

# Streamlit UI elements for patient prediction
if 'user' in st.session_state:
    st.subheader("Enter Patient Details for Prediction")
    name = st.text_input("Enter Your Name")
    gender = st.number_input("Gender (0: Male, 1: Female)")
    age = st.slider("Select Your Age", 0, 150)
    bmi = st.number_input("BMI")
    fbg = st.number_input("FBG")
    postprandial_glucose = st.number_input("2 Hour Postprandial Glucose")
    hba1c = st.number_input("Hba1c")
    family_history = st.number_input("Family History (1: Yes, 0: No)")
    urine_microalbumin = st.number_input("Urine Microalbumin")
    urine_glucose = st.number_input("Urine Glucose (0: Normal, 1: Abnormal)")
    urine_ketones = st.number_input("Urine Ketones (0: Normal, 1: Abnormal)")
    lipid_profile = st.number_input("Lipid Profile (0: Normal, 1: Abnormal)")
    physical_activity = st.number_input("Physical Activity (0: No, 1: Yes, 2: Someday)")
    systolic_bp = st.number_input("Systolic BP")
    diastolic_bp = st.number_input("Diastolic BP")

    submitted = st.button("Predict")

    # Save user input and prediction result in session state
    if submitted:
        prediction_result = predict_diabetes_class(age, bmi, fbg, postprandial_glucose, hba1c, urine_microalbumin, urine_glucose, urine_ketones, lipid_profile, systolic_bp, diastolic_bp)
        st.success(f"Diabetes Prediction: {prediction_result}")

        # Generate fake values for additional columns
        patient_id, date, referred_by, lab = generate_fake_values()

        # Prepare the data in the correct format
        new_row = {
            'Patient ID': patient_id,
            'Patient Name': name,
            'Gender (0: Male, 1: Female)': gender,
            'Age': age,
            'BMI': bmi,
            'FBG': fbg,
            '2 HOUR POSTPRANDIAL GLUCOSE': postprandial_glucose,
            'HbA1c': hba1c,
            'Family History (0: No, 1: Yes)': family_history,
            'Urine Microalbumin': urine_microalbumin,
            'Urine Glucose (0: Normal, 1: Abnormal)': urine_glucose,
            'Urine Ketones (0: Normal, 1: Abnormal)': urine_ketones,
            'Lipid Profile (Normal/Abnormal)': lipid_profile,
            'Physical Activity': physical_activity,
            'Date': date,
            'Referred By': referred_by,
            'Lab': lab,
            'Diabetes Prediction': prediction_result,
            'Systolic BP': systolic_bp,
            'Diastolic BP': diastolic_bp
        }

        # Append user input to existing dataset
        try:
            existing_dataset = existing_dataset.append(new_row, ignore_index=True)
            existing_dataset.to_csv(existing_dataset_path, index=False)
            st.success("Data saved successfully.")
        except PermissionError as e:
            st.error(f"Permission error: {e}")
        except Exception as e:
            st.error(f"An error occurred while saving the dataset: {e}")

        # Generate PDF report
        pdf_file_path = generate_pdf_report(patient_id, name, gender, age, bmi, fbg, postprandial_glucose, hba1c, family_history, urine_microalbumin, urine_glucose, urine_ketones, lipid_profile, physical_activity, date, referred_by, lab, systolic_bp, diastolic_bp, prediction_result)

        # Provide link to download the PDF
        with open(pdf_file_path, "rb") as f:
            st.download_button(
                label="Download PDF Report",
                data=f,
                file_name="Diabetes_Report.pdf",
                mime="application/pdf"
            )

        # Clean up the temporary file
        os.remove(pdf_file_path)
