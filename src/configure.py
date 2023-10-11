import mysql.connector
import getpass
import hashlib
import string
import random
import colorama

DEFAULT_PASSWORD_LENGTH = 12
RED = colorama.Fore.RED
GREEN = colorama.Fore.GREEN
YELLOW = colorama.Fore.YELLOW
RESET = colorama.Style.RESET_ALL

def configure_database():
    try:
        # Attempt to establish a connection to the MySQL database server
        database = mysql.connector.connect(
            host = 'localhost',
            user = 'username',
            password = 'password'
        )
    except Exception as e:
        # If an exception occurs during the connection attempt, print an error message
        print(RED + "Error during the configuration of the database." + RESET)
        return None
    # Return the established database connection
    return database

# Function to generate a random salt
def generate_salt(default_size=14):
    characters = string.ascii_letters + string.digits + string.punctuation
    salt = ''.join(random.sample(characters, default_size))
    return salt

def create_auth_record(database, cursor):
    # Get the master password and confirm it
    while True:
        master_password = getpass.getpass("Select a master password: ")
        confirmation = getpass.getpass("Confirm: ")
        if master_password == confirmation and len(master_password) > 0:
            break
        print("The passwords do not match, enter the password again: ")
    
    # Hash the master password and generate user salt
    hashed_master_password = hashlib.sha256(master_password.encode()).hexdigest()
    user_salt = generate_salt()
    print(GREEN + "Hash of the password generated successfully." + RESET)
    print(GREEN + "Salt for the user generated successfully." + RESET)

    # Insert the authentication record into the 'auth' table
    query = "INSERT INTO password_manager.auth(master_key_hash, user_salt) VALUES (%s, %s)"
    query_values = (hashed_master_password, user_salt)

    try:
        cursor.execute(query, query_values)
        database.commit()
        print(GREEN + "Authentication record inserted successfully." + RESET)
    except Exception as e:
        database.rollback()
        print(RED + "Error inserting authentication record: " + RESET, e)

def initialize_database():
    database = configure_database()
    if database == None:
        return

    cursor = database.cursor()
    try:
        # Attempt to create the 'password_manager' database
        cursor.execute("CREATE DATABASE password_manager")
        print(GREEN + "Database \"password_manager\" created successfully." + RESET)
    except Exception as e:
        # If the database already exists, inform the user and return the existing database connection
        print('Database \"password_manager\" exists.')
        return database
    
    # Define the SQL query to create the 'auth' table
    query = '''CREATE TABLE password_manager.auth (
        master_key_hash TEXT NOT NULL,
        user_salt TEXT NOT NULL
    )'''
    cursor.execute(query)
    print(GREEN + "\"auth\" table created successfully." + RESET)

    # Define the SQL query to create the 'credentials' table
    query = '''CREATE TABLE password_manager.credentials (
        email TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        website TEXT NOT NULL,
        url TEXT
    )'''
    cursor.execute(query)
    print(GREEN + "\"credentials\" table created successfully." + RESET)

    create_auth_record(database, cursor)
    return database