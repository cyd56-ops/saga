from typing import List
from pymongo import MongoClient
from saga.config import MONGO_URI_FOR_TOOLS


class BaseTool:
    """为本地工具提供共享的 MongoDB 存储和地址字段解析逻辑。"""

    def __init__(self, tool_name):
        self.tool_name = tool_name
        self.mongo_uri = MONGO_URI_FOR_TOOLS

        # Make sure relevant mongoDB will be available and created
        # db = self.client.get_database(self.tool_name)
        # collection = db.get_collection(self.username + "_inbox")

    def _clear_data(self):
        client = MongoClient(self.mongo_uri)
        db = client.get_database(self.tool_name)
        # Purge all data in this tool's storage
        for collection_name in db.list_collection_names():
            collection = db.get_collection(collection_name)
            collection.delete_many({})
        client.close()

    def _get_email_from_field(self, text: str) -> str:
        """
            Field will be in the format "name <email>", or just the email
            We want to extract the email address from this field
        """
        if not ("<" in text and ">" in text):
            return text.strip()

        return text.split("<")[1].split(">")[0]

    def _get_name_from_field(self, text: str) -> str:
        """
            Field will be in the format "name <email>"
            We want to extract the name from this field
        """
        return text.split("<")[0].strip()

    def seed_data(self, data: List[dict]):
        """
            Child class should implement a method to seed tool with specified data
        """
        raise NotImplementedError("Child class should implement a method to seed tool with specified data")
