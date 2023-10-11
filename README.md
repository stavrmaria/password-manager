# Password Manager
This is a simple command-line password manager that allows you to insert, delete, and search for password entries. The password manager is written in Python and uses a local mySQL database to store the password entries.

## Installation
To install the password manager, you will need to have Python 3 and mySQL installed on your system. You can then clone the repository and install the dependencies using pip:
```
git clone https://github.com/stavrmaria/password-manager.git
cd password-manager
```
**Note**: make sure you configure your username and password for the SQL connection to the database in the [`configure.py`](src/configure.py).

## Usage
To start the password manager, run the password_manager.py script:
```
python main.py <function> <args>
```
Here are supported the arguments for the script.
| Command | Description | Options |
| ----------- | ----------- | ----------- |
| `--help`, `-h` | Displays the help message | |
| `insert`, `i` | Insert a new entry in the database | `-n`, `-e`, `-w`, `-u` |
| `search`, `s` | Searches for entries in the database | `-n`, `-e`, `-w`, `-u` |
| `remove`, `r` | Remove a password entry | `-n`, `-e`, `-w`, `-u` |
| `generate`, `g` | Generate a password (default = 12) | `-l` |

The options are:
- `-n`: username of the user
- `-e`: email of the user
- `-w`: name  of the website
- `-u`: name  of the URL
- `-l`: the length of the password

## Security
The password manager uses AES encryption to encrypt the password entries before storing them in the database. The encryption key is generated from a user-specified master password using the PBKDF2 key derivation function with a random salt.
