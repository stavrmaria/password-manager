import argparse
import getpass
import hashlib
import clipboard
import colorama
from configure import initialize_database
from configure import DEFAULT_PASSWORD_LENGTH, RED, GREEN, YELLOW, RESET
from actions import insert_entry, search_entry, delete_entry, generate_password, get_password, display

def authenticate_user(cursor, master_password):
    hashed_master_password = hashlib.sha256(master_password.encode()).hexdigest()
    
    # Query the 'auth' table to retrieve stored data
    query = 'SELECT * FROM password_manager.auth'
    cursor.execute(query)
    output = cursor.fetchall()

    # Check if the hashed master password matches the stored hash
    if hashed_master_password != output[0][0]:
        print(RED + 'The password you entered does not match the master password.' + RESET)
        exit(1)
    return (master_password, output[0][1])

def initialize():
    # Get a connection to the database
    database = initialize_database()
    cursor = database.cursor()
    
    # Prompt the user for the master password and authenticate
    master_password = getpass.getpass('Master password: ')
    master_password, user_salt = authenticate_user(cursor, master_password)

    database.close()
    cursor.close()
    return (master_password, user_salt)

# Create a dictionary of the arguments
def get_arguments(args):
    arguments = {}
    if args.username is not None:
        arguments["username"] = args.username
    if args.email is not None:
        arguments["email"] = args.email
    if args.website is not None:
        arguments["website"] = args.website
    if args.url is not None:
        arguments["url"] = args.url
    return arguments

if __name__ == "__main__":
    colorama.init()
    parser = argparse.ArgumentParser()
    parser.add_argument('option', help='(i)nsert / (s)earch / (g)enerate / d(elete)')
    parser.add_argument("-e", "--email", help="Email of the user")
    parser.add_argument("-n", "--username", help="Username")
    parser.add_argument("-w", "--website", help="Name of the website")
    parser.add_argument("-u", "--url", help="URL of the website")
    parser.add_argument("-l", "--length", help="Length of the password", type=int)
    args = parser.parse_args()

    auth_credentials = initialize()
    arguments = get_arguments(args)

    # Generate a password and save it to the clipboard
    if args.option in ['g', 'generate']:
        password_length = DEFAULT_PASSWORD_LENGTH if args.length is None else args.length
        new_password = generate_password(password_length)
        clipboard.copy(new_password)
        print(f"Generating password of length {password_length}...")
        print(GREEN + f"New password copied to clipboard successfully." + RESET)
    
    # Insert a new entry in the credentials table
    if args.option in ['i', 'insert']:
        print('Inserting the new entry...')
        entries = search_entry(arguments)
        if entries is not None:
            print(YELLOW + f"There are {len(entries)} entries matching the provided arguments." + RESET)
            print(YELLOW + "Please provide more specific arguments to avoid duplicates." + RESET)
            exit(0)
        insert_entry(auth_credentials, arguments)
        print(GREEN + 'Entry added successfully to the database.' + RESET)
    
    # Search for entry in the credentials table
    if args.option in ['s', 'search']:
        print('Searching for entries...')
        entries = search_entry(arguments)
        if entries is not None:
            display(entries)
        
            if len(entries) == 1:
                while True:
                    decrypt_option = input('Do you want to decrypt the password? (y/n): ')
                    if len(decrypt_option) == 1 and (decrypt_option.lower() == 'y' or decrypt_option.lower() == 'n'):
                        break
                    print('Invalid input, please enter again: ')
                
                if decrypt_option.lower() == 'y':
                    clipboard.copy(get_password(auth_credentials, entries))
                    print(GREEN + 'Password copied to clipboard.' + RESET)
        else:
            print("No entries found.")
        print(GREEN + 'Search completed.' + RESET)
    
    # Delete an entry from the credentials table
    if args.option in ['d', 'delete']:
        print('Delete entries...')
        entries = search_entry(arguments)
        
        if entries is not None:
            display(entries)
            delete_entry(arguments)
        print(GREEN + 'Entries deleted successfully.' + RESET)