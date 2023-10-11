import getpass
import secrets
import string
from tabulate import tabulate
from configure import configure_database
from configure import RED, RESET
from crypto_actions import calculate_master_key, encrypt, decrypt

# Function to return a tuple of the arguments values
def get_argument_values(arguments):
    email = arguments["email"] if "email" in arguments else None
    username = arguments["username"] if "username" in arguments else None
    website = arguments["website"] if "website" in arguments else None
    url = arguments["url"] if "url" in arguments else None
    return (email, username, website, url)

def insert_entry(auth_credentials, arguments):
    # Check if all required credentials are provided
    if "username" not in arguments or "email" not in arguments or "website" not in arguments:
        print(RED + "The required credentials are not provided (username, email, website)" + RESET)
        exit(1)
    
    # Prompt the user for a new password and confirmation
    while True:
        new_password = getpass.getpass("Select a new password: ")
        confirmation = getpass.getpass("Confirm: ")
        if new_password == confirmation and len(new_password) > 0:
            break
        print("The passwords do not match, enter the password again: ")
    
    # Calculate the master key and encrypt the new password
    master_key = calculate_master_key(auth_credentials)
    encrypted_password = encrypt(master_key, new_password)
    (email, username, website, url) = get_argument_values(arguments)
    
    # Insert the encrypted entry into the 'credentials' table
    database = configure_database()
    cursor = database.cursor()
    query = '''INSERT INTO password_manager.credentials 
    (email, username, password, website, url) values (%s, %s, %s, %s, %s)'''
    query_values = (email, username, encrypted_password, website, url)
    cursor.execute(query, query_values)
    database.commit()

    cursor.close()
    database.close()

def search_entry(arguments):
    database = configure_database()
    cursor = database.cursor()

    # If no specific arguments provided, fetch all entries
    if len(arguments) == 0:
        query = "SELECT * FROM password_manager.credentials"
    else:
        # Build the query for filtering based on provided arguments
        query = "SELECT * FROM password_manager.credentials WHERE "
        for arg_name, arg_value in arguments.items():
            query += f"{arg_name} = \'{arg_value}\' AND "
        query = query[:-4]
    
    # Execute the query and fetch the results
    cursor.execute(query)
    output = cursor.fetchall()
    cursor.close()
    database.close()

    if len(output) == 0:
        return None
    return output

def delete_entry(arguments):
    # If no specific arguments provided, fetch all entries
    database = configure_database()
    cursor = database.cursor()

    # Ask for user confirmation
    while True:
        option = input("Are you sure you want to delete these enctries? (y/n): ")
        if len(option) == 1 and (option.lower() == 'y' or option.lower() == 'n'):
            break
        print("Invalid input, please enter again: ")
    if option.lower() != 'y':
        return

    # Build the DELETE query based on provided arguments
    if len(arguments) == 0:
        query = "DELETE FROM password_manager.credentials"
    else:
        query = "DELETE FROM password_manager.credentials WHERE "
        for arg_name, arg_value in arguments.items():
            query += f"{arg_name} = \'{arg_value}\' AND "
        query = query[:-4]
    
    # Execute the DELETE query and commit changes
    cursor.execute(query)
    database.commit()
    database.close()
    cursor.close()

# Function to generate a random password of the given length
def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for i in range(length))

# Function to retrieve a decrypted password from an entry using auth_credentials
def get_password(auth_credentials, entry):
    encrypted_password = entry[0][2]
    master_key = calculate_master_key(auth_credentials)
    decrypted_master_key = decrypt(master_key, encrypted_password)
    return decrypted_master_key

# Get the number of entries in the database
def count_entries():
    database = configure_database()
    cursor = database.cursor()
    query = "SELECT COUNT(*) FROM password_manager.credentials"
    cursor.execute(query)
    num_entries = cursor.fetchone()[0]
    database.close()
    cursor.close()
    return num_entries

# Function to display retrieved data in a formatted table
def display(data):
    total_entries = count_entries()
    field_names = ['Email', 'Username', 'Password', 'Website', 'URL']
    print(f"{len(data)}/{total_entries} entries found:")
    print('\n' + tabulate(data, headers=field_names, tablefmt='psql') + '\n')