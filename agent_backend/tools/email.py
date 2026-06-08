from pymongo import MongoClient
from datetime import datetime
from typing import List

from agent_backend.tools.base import BaseTool


class LocalEmailClientTool(BaseTool):
    """封装本地邮件工具的收件箱、发件箱和搜索写入能力。"""

    def __init__(self, user_name: str, user_email: str):
        super().__init__("email")
        self.client = MongoClient(self.mongo_uri)
        self.user_email = user_email
        self.user_name = user_name
    
    def seed_data(self, data: List[dict]):
        """把测试邮件按发件人/收件人分发到本地 MongoDB 集合。"""
        db = self.client.get_database(self.tool_name)
        collection_self = db.get_collection(self.user_email + "_sent")

        for email in data: 
            # If email is from self, add to sent collection
            if email["from"] == f"{self.user_name} <{self.user_email}>":
                collection_self.insert_one(email)
                continue

            recepients = email["to"]

            for recipient in recepients:
                # format is "name <email>" - we want email out of it
                recipient = self._get_email_from_field(recipient)
                collection_recipient = db.get_collection(recipient + "_inbox")
                # Insert into recipient inbox collection
                collection_recipient.insert_one(email)
    
    def get_emails(self, where: str, limit: int = 10):
        """
        This method retrieves emails from the database.
        Returns a list of dictionaries containing the email details.
        """
        db = self.client.get_database(self.tool_name)
        if where not in ["inbox", "sent"]:
            raise ValueError(f"Invalid search location: {where}. Must be 'inbox' or 'sent'.")

        collection = db.get_collection(self.user_email + f"_{where}")
        # Get 'limit' most recent emails. If limit is None, get all emails.
        emails = collection.find().sort("time:", -1)
        if limit is not None:
            emails = emails.limit(limit)

        # Convert to list of dictionaries
        emails = list(emails)
        # Remove objectid : we only need from/subject/body/time
        for email in emails:
            email.pop("_id", None)

        return emails

    def search_by_query(self, query: str, where: str):
        """
        This method searches for emails that match the query across any field.
        Returns a list of dictionaries containing the email details, sorted by time.
        """
        db = self.client.get_database(self.tool_name)
        if where not in ["inbox", "sent"]:
            raise ValueError(f"Invalid search location: {where}. Must be 'inbox' or 'sent'.")

        collection = db.get_collection(self.user_email + f"_{where}]")
        # TODO: MIGHT BE SOMETHING WRONG WITH SEARCH FUNCTIONALITY HERE. LOOK INTO IT AT SOME POINT
        
        # Search for emails where any field matches the query
        emails = collection.find({
            "$or": [
                {"from": {"$regex": query, "$options": "i"}},
                {"subject": {"$regex": query, "$options": "i"}},
                {"body": {"$regex": query, "$options": "i"}},
                {"time:": {"$regex": query, "$options": "i"}}
            ]
        })
        
        # Convert to list of dictionaries
        emails = list(emails)

        # Sort by 'time' (we want latest first)
        emails.sort(key=lambda x: x["time:"], reverse=True)

        # Remove objectid : we only need from/subject/body/time
        for email in emails:
            email.pop("_id", None)
        return emails

    def send_email(self, to: List[str], subject: str, body: str):
        """
        This method sends an email to the specified recipient(s).
        Returns True if the email was sent successfully, False otherwise.
        """
        db = self.client.get_database(self.tool_name)
        collection_self = db.get_collection(self.user_email + "_sent")

        # TODO: Check if receipent exists
        # if to + "_inbox" not in db.list_collection_names():
        #     print(db.list_collection_names())
        #     raise ValueError(f"Recipient inbox for {to} does not exist")
        
        time_sent = datetime.now()
        
        for receipient in to:
            email = {
                "from": f"{self.user_name} <{self.user_email}>",
                "to": to,
                "subject": subject,
                "body": body,
                "time:": time_sent
            }

            # Insert into recipient inbox collection
            collection_recipient = db.get_collection(receipient + "_inbox")
            collection_recipient.insert_one(email)
        
        # Insert into self sent collection
        collection_self.insert_one(email)

        return True
