"""Tests for local calendar storage behavior."""

from __future__ import annotations

from typing import Any
import unittest
from unittest import mock

from bson import ObjectId

from agent_backend.tools.calendar import LocalCalendarTool


class FakeCalendarCollection:
    """模拟 Mongo collection 插入时会原地写入 `_id` 的行为。"""

    def __init__(self) -> None:
        self.documents: list[dict[str, Any]] = []

    def insert_one(self, document: dict[str, Any]) -> object:
        """记录插入文档，并复现 PyMongo 对原始 dict 注入 `_id` 的副作用。"""
        document.setdefault("_id", ObjectId())
        self.documents.append(dict(document))
        return object()


class FakeCalendarDatabase:
    """按 collection name 保存 fake 日历集合。"""

    def __init__(self) -> None:
        self.collections: dict[str, FakeCalendarCollection] = {}

    def get_collection(self, name: str) -> FakeCalendarCollection:
        """返回指定用户邮箱对应的 fake collection。"""
        return self.collections.setdefault(name, FakeCalendarCollection())


class FakeMongoClient:
    """提供 LocalCalendarTool 所需的最小 MongoClient 接口。"""

    database = FakeCalendarDatabase()

    def __init__(self, mongo_uri: str) -> None:
        self.mongo_uri = mongo_uri

    def get_database(self, name: str) -> FakeCalendarDatabase:
        """返回共享 fake calendar 数据库。"""
        return self.database


class LocalCalendarToolTests(unittest.TestCase):
    """Validate calendar event insertion edge cases."""

    def setUp(self) -> None:
        """每个测试前重置共享 fake 数据库，避免集合状态串扰。"""
        FakeMongoClient.database = FakeCalendarDatabase()

    @mock.patch("agent_backend.tools.calendar.MongoClient", FakeMongoClient)
    def test_add_calendar_event_deduplicates_participants_by_email(self) -> None:
        """同一邮箱的不同显示格式不应导致重复插入或半写入。"""
        calendar = LocalCalendarTool(user_name="Raj Sharma", user_email="raj.sharma@gmail.com")

        added = calendar.add_calendar_event(
            time_from="2026-05-19 09:00:00",
            time_to="2026-05-19 09:30:00",
            event="NDSS Submission Discussion",
            details="Discuss submission status.",
            participants=["emma_johnson@gmail.com", "raj.sharma@gmail.com"],
        )

        self.assertTrue(added)
        database = FakeMongoClient.database
        emma_documents = database.get_collection("emma_johnson@gmail.com").documents
        raj_documents = database.get_collection("raj.sharma@gmail.com").documents
        self.assertEqual(len(emma_documents), 1)
        self.assertEqual(len(raj_documents), 1)
        self.assertEqual(emma_documents[0]["event"], raj_documents[0]["event"])
        self.assertEqual(emma_documents[0]["time_from"], raj_documents[0]["time_from"])
        self.assertEqual(
            emma_documents[0]["participants"],
            ["emma_johnson@gmail.com", "raj.sharma@gmail.com"],
        )


if __name__ == "__main__":
    unittest.main()
