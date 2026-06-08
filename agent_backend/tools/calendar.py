from pymongo import MongoClient
from datetime import datetime, timedelta, time
from typing import List

from agent_backend.tools.base import BaseTool


class LocalCalendarTool(BaseTool):
    """封装本地日历工具的存储、查询和写入能力。"""

    def __init__(self, user_name: str, user_email: str):
        super().__init__("calendar")
        self.client = MongoClient(self.mongo_uri)
        self.user_name = user_name
        self.user_email = user_email
        # TODO: Do not hard-code policy
        self.policy = {
            "start_time": "09:00:00",
            "end_time": "17:00:00",
            "start_day": "Monday",
            "end_day": "Friday"
        }
    
    def get_preference(self):
        """返回当前硬编码日历策略对应的可读会议偏好。"""
        return "Any time between {} and {} between {} and {} in the week".format(
            self.policy["start_time"],
            self.policy["end_time"],
            self.policy["start_day"],
            self.policy["end_day"]
        )

    def seed_data(self, data: List[dict]):
        """将测试日历数据写入本人和参会人的日历集合。"""
        db = self.client.get_database(self.tool_name)
        collection_self = db.get_collection(self.user_email)

        for event in data:
            event["time_from"] = datetime.fromisoformat(event["time_from"])
            event["time_to"] = datetime.fromisoformat(event["time_to"])

            # Insert into self sent collection
            collection_self.insert_one(event)

            # format is "name <email>" - we want email out of it
            participants = event["participants"]
            for participant in participants:
                participant_email = self._get_email_from_field(participant)

                # Insert into recipient calendar collection, as long as the receipient is not self
                if participant_email != self.user_email:
                    collection_participant = db.get_collection(participant_email)
                    collection_participant.insert_one(event)
    
    def get_upcoming_events(self, limit: int = 10):
        """
        This method retrieves a list of upcoming events from the user's calendar.
        Returns a list of dictionaries containing the event details.
        """
        db = self.client.get_database(self.tool_name)
        collection = db.get_collection(self.user_email)
        
        # We want all calendar events that have not already ended
        now = datetime.now()
        events = collection.find({"time_to": {"$gte": now}}).sort("time_from", 1)
        if limit is not None:
            events = events.limit(limit)
        
        # Convert to list of dictionaries
        events = list(events)
        # Remove objectid : we only need to/from/subject/body/time
        for email in events:
            email.pop("_id", None)
        return events

    def get_availability(self, time_from: str, time_to: str):
        """
        This method retrieves all events within the specified time-range, and then return the blocks of times where the user is free.
        """
        db = self.client.get_database(self.tool_name)
        collection = db.get_collection(self.user_email)

        current = datetime.fromisoformat(time_from)
        end_time_dt = datetime.fromisoformat(time_to)

        # We want all calendar events that are within the specified time range
        events = collection.find({
            "$or": [
                {"time_from": {"$gte": current, "$lte": end_time_dt}},
                {"time_to": {"$gte": current, "$lte": end_time_dt}},
                {"time_from": {"$lte": current}, "time_to": {"$gte": end_time_dt}}
            ]
        }).sort("time_from", 1)

        # Normalize start and end of policy hours for a given date
        def policy_bounds(dt):
            """计算某一天允许安排会议的策略时间边界。"""
            date_only = dt.date()
            start = datetime.combine(date_only, time.fromisoformat(self.policy["start_time"]))
            end = datetime.combine(date_only, time.fromisoformat(self.policy["end_time"]))
            return start, end

        # Helper to clip an interval [start_dt, end_dt) to policy hours, splitting across days if needed.
        def clip_to_policy(start_dt, end_dt):
            """把候选空闲区间裁剪到策略允许的每日工作时间内。"""
            blocks = []
            current = start_dt
            # Process day-by-day.
            while current < end_dt:
                day_start, day_end = policy_bounds(current)
                # Advance current to next day's policy start if it's before policy hours.
                if current < day_start:
                    current = day_start
                # Determine the block end for the day.
                block_end = min(end_dt, day_end)
                if current < block_end:
                    blocks.append({"start": current.isoformat(), "end": block_end.isoformat()})
                # Move to next day.
                current = datetime.combine(current.date() + timedelta(days=1), time.fromisoformat(self.policy["start_time"]))
            return blocks

        # Start from the query's starting datetime.
        free_times = []

        # Iterate through all events in order.
        for event in events:
            event_start = event["time_from"]
            event_end = event["time_to"]

            # Skip events that end before our current pointer.
            if event_end <= current:
                continue

            # Adjust event_start if the event starts before 'current'.
            effective_event_start = max(event_start, current)

            # If there's a gap before this event starts, register it.
            if effective_event_start > current:
                free_gap_start = current
                free_gap_end = effective_event_start
                # Clip the free interval to policy hours.
                free_times.extend(clip_to_policy(free_gap_start, free_gap_end))

            # Move current pointer to the end of the event if it's later.
            current = max(current, event_end)
            if current >= end_time_dt:
                break

        # Any remaining time after the last event.
        if current < end_time_dt:
            free_times.extend(clip_to_policy(current, end_time_dt))

        return free_times


    def add_calendar_event(self,
                           time_from: str,
                           time_to: str,
                           event: str,
                           participants: List[str],
                           details: str) -> bool:
        """向所有参会人的本地日历集合写入同一个会议事件。"""
        db = self.client.get_database(self.tool_name)

        # Make sure time_from and time_to are ISO format
        try:
            # You can try to parse the string to a datetime object here if needed
            time_from = datetime.fromisoformat(time_from)
        except ValueError:
            print("Invalid date format for time_from")
        
        try:
            time_to = datetime.fromisoformat(time_to)
        except ValueError:
            print("Invalid date format for time_to")
        
        participants_by_email: dict[str, str] = {}
        for participant in participants:
            participant_email = self._get_email_from_field(participant)
            # 同一邮箱可能以纯邮箱或 "Name <email>" 出现，必须按邮箱语义去重。
            if participant_email:
                participants_by_email.setdefault(participant_email, participant.strip())

        if self.user_email not in participants_by_email:
            participants_by_email[self.user_email] = f"{self.user_name} <{self.user_email}>"

        normalized_participants = list(participants_by_email.values())

        event = {
            "time_from": time_from,
            "time_to": time_to,
            "event": event,
            "participants": normalized_participants,
            "details": details,
        }

        # Now add it to the calendar of all participants
        for participant_email in participants_by_email:
            collection = db.get_collection(participant_email)
            collection.insert_one(dict(event))

        return True
