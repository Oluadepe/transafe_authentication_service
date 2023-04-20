#!/usr/bin/env python3
"""
Manages CRUD operations on Mongo database
"""
from typing import List, Dict, Union
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from utils import check_password
from dotenv import load_dotenv
from os import getenv


load_dotenv()


class Database:
    """
    Mongo database class
    """
    __collection = None
    __db = None

    def __init__(self):
        """
        Initializes database connection
        """
        username = getenv('username')
        password = getenv('password')

        # MongoDB Atlas cluster
        uri = getenv('cluster_uri').format(username, password)

        client = MongoClient(uri, server_api=ServerApi('1'))
        self.__db = client[getenv('database')]
        self.__collection = self.__db[getenv('collection')]

    def all(self) -> Union[List[Dict], None]:
        """
        retrieve all user credentials from database
        """
        try:
            data = list(self.__collection.find({}, {'_id': 0}))
            return data
        except Exception:
            return None

    def get(self, email: str, user_id: str) -> Union[Dict, None]:
        """
        retrieve document from database by email
        """
        user_data = self.__collection.find_one({'$or': [{'id': user_id},
                                                        {'email': email}]},
                                               {'_id': 0})
        return user_data

    def get_one(self, email: str) -> Dict:
        """
        """
        user = self.__collection.find_one({'email': email}, {'_id': 0})
        return user

    def add(self, obj: Dict) -> bool:
        """
        add new document to database
        """
        required_field = ['email', 'role', 'password', 'id']
        if not all(item in obj for item in required_field):
            return False
        user_exist = self.get(email=obj.get('email'), user_id=obj.get('id'))
        if user_exist is not None:
            return False
        if obj.get('email') is not None or obj.get('email') != '':
            if len(obj) == 6:
                if 'password' in obj and len(obj.get('password')) > 59:
                    if isinstance(obj.get('password'), bytes):
                        self.__collection.insert_one(obj)
                        return True

    def delete(self, filt: Dict) -> None:
        """
        deletes document in database
        """
        if filt.get('password') is None and filt.get('email') is None:
            return
        hash_password = self.get(email=filt.get('email')).get('password')
        if check_password(filt.get('password'), hash_password):
            filt.pop('password')
            print('filt: ', filt)
            self.__collection.delete_one(filt)

    def update(self, filt: Dict, data_to_update: Dict) -> Union[int, None]:
        """
        update document in database
        """
        if filt.get('email') is None or filt.get('email') == '':
            return None
        feedback = self.__collection.update_one(filt, {'$set': data_to_update})
        return feedback.modified_count
