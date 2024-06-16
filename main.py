# Simple code for CRUD operations APIs in FastAPI
# Database: sqlite3

from fastapi import FastAPI, HTTPException, Request
import asyncio
import sqlite3
import re
from dateutil import parser
import hashlib
import smtplib
from email.message import EmailMessage


crud_app = FastAPI()

sqliteConnection = sqlite3.connect(r'C:\Users\naiti\OneDrive\Desktop\AI Project-2\Project-1\user_project_data.db')

cursor = sqliteConnection.cursor()

user_table_a = "USER_PROJECT_A"
user_table_b = "USER_PROJECT_B"
user_table_c = "USER_PROJECT_C"

receiver_emails = ["naitiksoni.ai@gmail.com", "naitiksoni1705@gmail.com"] #["shraddha@aviato.consulting", "pooja@aviato.consulting"]

salt = "dbjk#NOI32%#VWA@SDcw3@&"

# Validator function for validating user data
def validate_user_details(user_data):
    validation = {
        "error": None,
        "user_data": dict(user_data)
    }

    # Check for empty data in json
    for key, value in validation["user_data"].items():
        if value == "":
            validation["error"] = "Error: " + key + " is empty"
            return validation
        validation["user_data"][key] = value.strip()
        
    # Validate first name and last name
    first_name, last_name = validation["user_data"]["first_name"], validation["user_data"]["last_name"]
    if not re.match(r'^[a-zA-Z\s]+$', first_name):
        validation["error"] = "First name is not valid"
        return validation
    
    if not re.match(r'^[a-zA-Z\s]+$', last_name):
        validation["error"] = "Last name is not valid"
        return validation

    # Validate email
    if "email" in validation["user_data"]:
        email = validation["user_data"]["email"]
        regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    
        if not re.match(regex, email):
            validation["error"] = "Invalid email address"
            return validation
        
    # Validate phone_number
    if "phone_number" in validation["user_data"]:
        pattern = r"^\d{10}$"
        if not re.match(pattern, validation["user_data"]["phone_number"]):
            validation["error"] = "Phone number not valid"
            return validation
        
    # Validate date format
    if "dob" in validation["user_data"]:
        try:
            date_obj = parser.parse(validation["user_data"]["dob"])
        except:
            validation["error"] = "Date format not valid"
            return validation
        
    if "password" in validation["user_data"]:
        if len(validation["user_data"]["password"])<8:
            validation["error"] = "Password should be atleast 8 characters long"
            return validation
        
    return validation

# Function for checking if user_id exists or not
async def check_userid(user_id, table_name):
    query = f"SELECT 1 FROM {table_name} WHERE ID = {user_id};"
    cursor.execute(query)
    if cursor.fetchone():
        await cursor.execute("COMMIT")
        return True
    return False

# This endpoint creates a new user
@crud_app.post("/add_user/")
async def create_user(request: Request, project_id: int):
    try:
        user_data = await request.json()
    except:
        return {"message": "Please provide json of user data"}

    validation = validate_user_details(user_data)
    
    if validation["error"] is not None:
        raise HTTPException(status_code=400, detail=validation["error"])

    user_data = validation["user_data"]

    first_name = user_data["first_name"]
    last_name = user_data["last_name"]

    if project_id==1:
        company_name = user_data["company_name"]
        email = user_data["email"]
        password = user_data["password"]
        # Secure password with SHA 256 algorithm
        password = hashlib.sha256((password + salt).encode()).hexdigest()

        query = f"INSERT INTO {user_table_a} (company_name, first_name, last_name, email, password) VALUES (?, ?, ?, ?, ?)"
        cursor.execute(query, (company_name, first_name, last_name, email, password))
        user_data["user_id"] = cursor.lastrowid

    elif project_id==2:
        mobile_number = user_data["phone_number"]
        hashtag = user_data["hashtag"]

        query = f"INSERT INTO {user_table_b} (phone_number, first_name, last_name, hashtag) VALUES (?, ?, ?, ?)"
        cursor.execute(query, (mobile_number, first_name, last_name, hashtag))
        user_data["user_id"] = cursor.lastrowid

    elif project_id==3:
        mobile_number = user_data["phone_number"]
        dob = user_data["dob"]

        query = f"INSERT INTO {user_table_c} (phone_number, first_name, last_name, dob) VALUES (?, ?, ?, ?)"
        cursor.execute(query, (mobile_number, first_name, last_name, dob))
        user_data["user_id"] = cursor.lastrowid

    else:
        raise HTTPException(status_code=400, detail="Invalid project_id given")
    
    cursor.execute("COMMIT")
    user_data["project_id"] = project_id
    print(f"LOG: New user added, user details: {user_data}")
    
    return user_data


# This endpoint is for retrieving all user details
@crud_app.get("/get_users")
async def get_users(project_id: int):
    table_name = None
    table_schema = None
    if project_id==1:
        table_name = user_table_a
        table_schema = ['user_id', 'company_name', 'first_name', 'last_name', 'email', 'password']
    elif project_id==2:
        table_name = user_table_b
        table_schema = ['user_id', 'phone_mumber', 'first_name', 'last_name', 'hashtag']
    elif project_id==3:
        table_name = user_table_c
        table_schema = ['user_id', 'phone_number', 'first_name', 'last_name', 'dob']
    else:
        raise HTTPException(status_code=400, detail="Invalid project_id given")

    query = f"SELECT * FROM {table_name}"
    cursor.execute(query)
    rows = cursor.fetchall()
    data = [dict(zip(table_schema, t)) for t in rows]

    return data


# This endpoint is for updating the user details
@crud_app.patch("/update_user/{user_id}")
async def update_user(request: Request, user_id: int, project_id: int):
    try:
        user_data = await request.json()
    except:
        return {"message": "Please provide json of user data"}
    
    validation = validate_user_details(user_data)
    
    if validation["error"] is not None:
        raise HTTPException(status_code=400, detail=validation["error"])

    user_data = validation["user_data"]

    first_name = user_data["first_name"]
    last_name = user_data["last_name"]

    if project_id==1:
        if not asyncio.run(check_userid(user_id, user_table_a)):
            return {"message": f"User with user_id={user_id} doesn't exist"}
        
        company_name = user_data["company_name"]
        email = user_data["email"]
        password = user_data["password"]

        query = f"""
            UPDATE {user_table_a}
            SET company_name = ?,
                first_name = ?,
                last_name = ?,
                email = ?,
                password = ?
            WHERE id = {user_id}
            """
        cursor.execute(query, (company_name, first_name, last_name, email, password))

    elif project_id==2:
        if not asyncio.run(check_userid(user_id, user_table_b)):
            return {"message": f"User with user_id={user_id} doesn't exist"}

        mobile_number = user_data["phone_number"]
        hashtag = user_data["hashtag"]

        query = f"""
            UPDATE {user_table_b}
            SET phone_number = ?,
                first_name = ?,
                last_name = ?,
                hashtag = ?
            WHERE id={user_id}
            """
        cursor.execute(query, (mobile_number, first_name, last_name, hashtag))

    elif project_id==3:
        if not asyncio.run(check_userid(user_id, user_table_c)):
            return {"message": f"User with user_id={user_id} doesn't exist"}

        mobile_number = user_data["phone_number"]
        dob = user_data["dob"]

        query = f"""
            UPDATE {user_table_c}
            SET first_name = ?,
                last_name = ?,
                dob = ?,
                phone_number = ?
            WHERE id = {user_id}
            """
        cursor.execute(query, (mobile_number, first_name, last_name, dob))

    else:
        raise HTTPException(status_code=400, detail="Invalid project_id given")
    
    await cursor.execute("COMMIT")
    user_data["user_id"] = user_id
    user_data["project_id"] = project_id
    print(f"LOG: User updated details, user details: {user_data}")
    
    return user_data


# This endpoint is for deleting a user
@crud_app.delete("/delete_user/{user_id}")
async def delete_user(user_id: int, project_id: int):
    table_name = None
    if project_id==1:
        table_name = user_table_a
    elif project_id==2:
        table_name = user_table_b
    elif project_id==3:
        table_name = user_table_c
    else:
        raise HTTPException(status_code=400, detail="Invalid project_id given")

    if not check_userid(user_id, project_id):
        return {"message": f"User with user_id={user_id} doesn't exist"}

    query = f"DELETE FROM {table_name} WHERE id = {user_id}"
    cursor.execute(query)
    await cursor.execute("COMMIT")
    print(f"LOG: User with user_id={user_id} deleted successfully from project={project_id}")
    
    return {"message": f"User with user_id={user_id} deleted successfully"}

# email password decoder
def decrypt_password(password):
    new_password = ""
    i = -1
    for char in password:
        i+=1
        new_password+=chr(ord(char)+23)

    password = new_password[12:] + new_password[4:8] + new_password[:4] + new_password[8:12]

    return password


# This endpoint is for sending email for api documentation
@crud_app.post("/send_mail/")
async def send_mail():
    EMAIL_USER = "naitiksoni1705@gmail.com"
    EMAIL_PASS = decrypt_password("S^c]OTc]MPXaUTac")

    msg = EmailMessage()
    msg['Subject'] = "Invitation email to FastAPI documentation(redoc)"
    msg['From'] = "naitiksoni1705@gmail.com"
    msg['To'] = receiver_emails[0]

    text = """
        Hi, here is the link to the api documentation of APIs created
        Link: {http/://127.0.0.1:8000/redoc}
    """
    msg.set_content(text)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as mail_sender_obj:
        mail_sender_obj.login(EMAIL_USER, EMAIL_PASS)
        mail_sender_obj.send_message(msg)