from pymongo import MongoClient
from typing import List
from datetime import datetime

from agent_backend.tools.base import BaseTool


class LocalDocumentsTool(BaseTool):
    """封装本地文档工具的测试数据写入、搜索和创建操作。"""

    def __init__(self, user_email: str):
        super().__init__("documents")
        self.client = MongoClient(self.mongo_uri)
        self.user_email = user_email
    
    def seed_data(self, data: List[dict]):
        """将文档测试数据写入当前用户的文档集合。"""
        db = self.client.get_database(self.tool_name)
        collection_self = db.get_collection(self.user_email)

        for document in data: 
            collection_self.insert_one(document)

    def search_by_query(self, query: str, limit: int = None) -> List[dict]:
        """
        Retrieve documents from the database based on the query.
        """
        db = self.client.get_database(self.tool_name)
        collection = db.get_collection(self.user_email)
        
        # Get 'limit' most recent documents.
        if query == "":
            documents = collection.find()
        else:
            # Search for documents where any field matches the query
            documents = collection.find({
                "$or": [
                    {"time": {"$regex": query, "$options": "i"}},
                    {"filename": {"$regex": query, "$options": "i"}},
                    {"content": {"$regex": query, "$options": "i"}},
                ]
            })
        documents = documents.sort("time", -1)  # Sort by time in descending order
        
        # If limit is None, get all documents.
        if limit is not None:
            documents = documents.limit(limit)
        
        # Convert to list of dictionaries
        documents = list(documents)

        # Remove objectid : we only need from/subject/body/time
        for document in documents:
            document.pop("_id", None)

        return documents

    def create_document(self, filename: str, content: str) -> bool:
        """
            Write document to file
        """
        db = self.client.get_database(self.tool_name)
        collection_self = db.get_collection(self.user_email)

        document = {
            "time": datetime.now(),
            "filename": filename,
            "content": content
        }
        collection_self.insert_one(document)
        return True
