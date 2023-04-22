import jwt
import bcrypt
import re
from os import getenv
from datetime import timedelta
from flask_jwt_extended import create_access_token

# email regexp
# encoding password and password validation


# hash password string
def hash_password(password_string: str) -> str:
    """
    hashes password string using bcrypt
    Args:
        - password_string (str): plain text password to hash

    Returns:
        - bytes: hashed password
    """
    return bcrypt.hashpw(password_string.encode('utf-8'), bcrypt.gensalt())


# Validate user inputed password
def check_password(password_string: str, hashed_password: bytes) -> bool:
    """
    validate password
    Args:
        - password_string (str): plain text password to check
        - hashed_password (bytes): previously hashed password to check against
    Return:
        bool: True if password match, False otherwise
    """
    if isinstance(password_string, str):
        return bcrypt.checkpw(password_string.encode('utf-8'), hashed_password)


# validate email format
def validate_email(email):
    """
    Return True if the given email address is valid, False otherwise.
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


# check ID string to validate UUID4 format
def is_valid_uuid(uuid_string):
    """
    Return True if uuid_string is a valid UUID, else False.
    """
    # following line is longer than 79 chars
    uuid_regex = re.compile(
        r'^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}$',
        re.I
    )
    match = uuid_regex.match(uuid_string)
    return bool(match)


def validate_password_format(password):
    """
    Validates password format.

    Return:
        - (bool): True if password is at least 8 chars long and
                  contains one uppercase, one lower character and a number,
                  otherwise False
    """
    pattern = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$'
    return re.match(pattern, password) is not None


def create_token(user_id):
    """
    creates user access token that's only valid for 5days

    Args:
        - user_id(str): users ID

    Returns:
        - (str): users access token
    """
    token = create_access_token(identity=user_id,
                                additional_claims={'role': 'user',
                                                   'iss': getenv('issuer')},
                                expires_delta=timedelta(days=5))
    return token
