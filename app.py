import streamlit as st
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import hashlib
import pandas as pd

# Set up Google Sheets API connection using credentials
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
creds = ServiceAccountCredentials.from_json_keyfile_name("credentials.json", scope)  # Replace with your creds file
client = gspread.authorize(creds)

# Open the Google Sheet by URL
sheet = client.open_by_url("https://docs.google.com/spreadsheets/d/1xoqqUuT716BOtWewzbMQHWU8BS8Hn76P8W3IguQHFh0/edit?usp=sharing")
user_sheet = sheet.worksheet("user")  # Specify the sheet name

# Fetch all records from the 'user' sheet
records = user_sheet.get_all_records()

# Convert the records to a pandas DataFrame
df = pd.DataFrame(records)

# Function to hash the password for storage
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Check if the user is admin
def is_admin(username, password):
    return username == "admin" and password == "admin_pass"

# Page for login
def login_page():
    st.title("Login Page")
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        # Admin check
        if is_admin(username, password):
            st.session_state["user"] = "admin"
            st.success("Logged in as admin")
            admin_page()
        else:
            # Check if the user exists in the Google Sheet
            user_data = df[df["Username"] == username]
            if not user_data.empty:
                stored_password_hash = user_data["Password"].values[0]
                if stored_password_hash == hash_password(password):
                    st.session_state["user"] = username
                    st.success(f"Logged in as {username}")
                    user_page(username)
                else:
                    st.error("Incorrect password")
            else:
                st.error("User not found")

# Admin page for creating users
def admin_page():
    st.title("Admin Panel")
    
    # User creation form
    with st.form(key="create_user_form"):
        new_username = st.text_input("New Username")
        new_password = st.text_input("New Password", type="password")
        submit_button = st.form_submit_button("Create User")
        
        if submit_button:
            if new_username and new_password:
                # Check if the username already exists in the sheet
                if new_username in df["Username"].values:
                    st.error("Username already exists")
                else:
                    # Add the new user to the dataframe
                    new_user = {"Username": new_username, "Password": hash_password(new_password)}
                    df = df.append(new_user, ignore_index=True)
                    
                    # Write the updated dataframe back to the sheet
                    user_sheet.update([df.columns.values.tolist()] + df.values.tolist())
                    
                    st.success(f"User {new_username} created successfully")
            else:
                st.error("Please fill out both fields")

# Page for a regular user after login
def user_page(username):
    st.title(f"Welcome {username}")
    st.write("This is your user page. You can view your data here.")

# Main entry point of the app
def main():
    if "user" not in st.session_state:
        login_page()
    else:
        user_role = st.session_state["user"]
        if user_role == "admin":
            admin_page()
        else:
            user_page(user_role)

if __name__ == "__main__":
    main()
