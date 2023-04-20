#!/usr/bin/env python3
"""
module provode class representing user account
"""
from datetime import datetime
from db import Database as storage
from utils import hash_password, validate_email, is_valid_uuid


class User:
    """
    user account class
    """
    def __init__(self, email, password, id):
        """
        Initializes user instance with email and hashed password
        """
        if validate_email(email):
            if is_valid_uuid(id):
                self.id = id
            self.email = email
            self.role = 'user'
            self.password = hash_password(password)
            self.created_at = datetime.utcnow()
            self.updated_at = datetime.utcnow()


    def to_dict(self):
        """
        returns dictionary of user object
        """
        my_dict = dict(self.__dict__)
        my_dict["created_at"] = self.created_at.isoformat()
        my_dict["updated_at"] = self.updated_at.isoformat()
        return my_dict

    def save(self):
        """
        save user instance to database

        Return: True if user is saved to database, False otherwise
        """
        return storage().add(self.__dict__)

    def delete(self, password):
        """
        deletes user instance
        """
        _dict = {
            "email": self.__dict__.get('email'),
            "password": password
            }
        storage().delete(_dict)

    def __str__(self):
        """
        string representation of object
        """
        return "[{:s}] with identity number: ({:s})\n{}\n{}\n{}".format(
               self.__class__.__name__, self.id, '*' * 75, self.__dict__,
               '*' * 75)
