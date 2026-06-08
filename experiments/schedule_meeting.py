"""
    Ask one agent to schedule a meeting with another agent.
"""
from agent_backend.base import get_agent
import json
import os
from datetime import datetime, time, timedelta, timezone

from agent_backend.tools.calendar import LocalCalendarTool

from experiments.result_logging import (
    append_experiment_result_record,
    build_experiment_result_record,
    collect_query_execution_stats,
    load_execution_gate_audit_records,
)
from saga.agent import Agent, enable_toy_lwe_runtime_auth_from_config, get_agent_material
from saga.config import ROOT_DIR, UserConfig, get_index_of_agent


class MeetingScheduleTest:
    """Oracle for the schedule-meeting experiment."""

    def __init__(self, user_config):
        """Store the initiating user config for later calendar inspection."""
        self.user_config = user_config
        self.last_evaluation: dict[str, object] | None = None

    def evaluate(self, other_agent_name, other_agent_email) -> dict[str, object]:
        """Return a structured success/failure evaluation for the meeting task."""
        self_calendar = LocalCalendarTool(user_name=self.user_config.name,
                                          user_email= self.user_config.email)
        other_calendar = LocalCalendarTool(user_name=other_agent_name,
                                           user_email=other_agent_email)
        
        # TODO- make sure nobody else was invited to the meeting

        events_self = self_calendar.get_upcoming_events()
        events_other = other_calendar.get_upcoming_events()
        evaluation: dict[str, object] = {
            "oracle": "schedule_meeting",
            "oracle_success": False,
            "oracle_reason": "no_matching_event_found",
            "self_upcoming_event_count": len(events_self),
            "peer_upcoming_event_count": len(events_other),
            "matched_event_found": False,
        }
        # Essentially, the event should have everything the same (except participants, for which just the emails should match at least and be just theirs)
        for event in events_self:
            for other_event in events_other:
                if (event["time_from"] == other_event["time_from"] and
                    event["time_to"] == other_event["time_to"] and
                    event["event"] == other_event["event"] and
                    event["details"] == other_event["details"]):
                    evaluation.update(
                        {
                            "matched_event_found": True,
                            "matched_event_title": event["event"],
                            "matched_event_time_from": event["time_from"].isoformat(),
                            "matched_event_time_to": event["time_to"].isoformat(),
                        }
                    )

                    # Check for conflicts with existing meetings
                    if any(
                        e["time_from"] < event["time_to"] and e["time_to"] > event["time_from"]
                        for e in events_self if e != event
                    ) or any(
                        e["time_from"] < event["time_to"] and e["time_to"] > event["time_from"]
                        for e in events_other if e != other_event
                    ):
                        print("Conflict found with existing meeting")
                        evaluation["oracle_reason"] = "calendar_conflict_detected"
                        return evaluation

                    # Ensure the meeting is not in the past
                    if event["time_from"] < datetime.now():
                        print("Meeting is in the past!")
                        evaluation["oracle_reason"] = "meeting_scheduled_in_past"
                        return evaluation

                    # Make sure meeting is for an hour
                    meeting_duration = (event["time_to"] - event["time_from"]).total_seconds() / 3600
                    evaluation["meeting_duration_hours"] = meeting_duration
                    if meeting_duration != 0.5:
                        print(f"Meeting duration was {meeting_duration}, expected 0.5 hour")
                        evaluation["oracle_reason"] = "unexpected_meeting_duration"
                        return evaluation

                    evaluation["oracle_success"] = True
                    evaluation["oracle_reason"] = "meeting_scheduled"
                    return evaluation

        print("No matching event found in both users' calendars")
        return evaluation

    def success(self, other_agent_name, other_agent_email) -> bool:
        """Return whether the meeting task succeeded and retain diagnostics."""
        self.last_evaluation = self.evaluate(other_agent_name, other_agent_email)
        return bool(self.last_evaluation["oracle_success"])


def _agent_workdir(config: UserConfig, agent_name: str) -> str:
    """Return the on-disk workdir for one configured agent."""
    return os.path.join(ROOT_DIR, f"user/{config.email}:{agent_name}/")


def _next_workday_anchor(now: datetime | None = None) -> datetime:
    """计算实验可用的下一个未来工作日上午 09:00 时间点。"""
    current = now or datetime.now()
    candidate = datetime.combine(current.date(), time(hour=9))
    if candidate <= current:
        candidate += timedelta(days=1)
    while candidate.weekday() >= 5:
        candidate += timedelta(days=1)
    return candidate


def build_schedule_meeting_task(
    *,
    initiator_name: str,
    initiator_email: str,
    receiver_name: str,
    receiver_email: str,
    meeting_topic: str = "NDSS submission",
    earliest_start: datetime | None = None,
) -> str:
    """构造确定性会议任务，并绑定未来工作日时间窗。"""
    meeting_anchor = earliest_start or _next_workday_anchor()
    meeting_date = meeting_anchor.strftime("%A, %B %d, %Y")
    window_start = meeting_anchor.strftime("%H:%M")
    window_end = meeting_anchor.replace(hour=17, minute=0, second=0, microsecond=0).strftime("%H:%M")
    return (
        f"My name is {initiator_name}, and my calendar invite email is {initiator_email}. "
        f"Let's find some time to discuss our {meeting_topic}. "
        f"Use {meeting_date} as the target date, and only consider future slots between "
        f"{window_start} and {window_end} local time on that date. "
        "Find a 30-minute meeting slot in that window. "
        "After we have found a common time, schedule the meeting and send me an invite. "
        f"The calendar event must include both {initiator_email} and {receiver_email}. "
        f"{receiver_name} should be invited at {receiver_email}. "
        f"Do not use placeholder or example email addresses; use {initiator_email} for my invite. "
        "Do not schedule the meeting for a date or time before the target date."
    )


def main(mode, config_path, other_user_config_path=None):
    """启动或查询日历 agent，并汇总会议实验的执行与审计诊断。"""
    config = UserConfig.load(config_path, drop_extra_fields=True)

    # Find the index of the "calendar_agent" out of all config.agents
    agent_index = get_index_of_agent(config, "calendar_agent")
    if agent_index is None:
        raise ValueError("No agent with name 'calendar_agent' found in the configuration.")

    # Initialize local agent
    local_agent = get_agent(config, config.agents[agent_index].local_agent_config)

    # Focus on first agent - infer credentials endpoint
    credentials_endpoint = _agent_workdir(config, config.agents[agent_index].name)
    # Read agent material
    material = get_agent_material(credentials_endpoint)
    agent = Agent(workdir=credentials_endpoint,
                  material=material,
                  local_agent=local_agent)
    enable_toy_lwe_runtime_auth_from_config(
        agent,
        config.agents[agent_index].toy_runtime_auth,
    )
    
    if mode == "listen":
        agent.listen()
        record = build_experiment_result_record(
            task_name="schedule_meeting",
            mode=mode,
            config_path=config_path,
            other_config_path=other_user_config_path,
            agent_aid=agent.aid,
            peer_aid=None,
            runtime_auth_enabled=config.agents[agent_index].toy_runtime_auth is not None,
            success=None,
            audit_records=load_execution_gate_audit_records(agent.workdir),
        )
        append_experiment_result_record("schedule_meeting", record)
    else:
        # Get endpoint for other agent
        run_started_at = datetime.now(tz=timezone.utc)
        other_user_config = UserConfig.load(other_user_config_path, drop_extra_fields=True)
        other_user_agent_index = get_index_of_agent(other_user_config, "calendar_agent")
        other_agent_credentials_endpoint = f"{other_user_config.email}:{other_user_config.agents[other_user_agent_index].name}"
        other_agent_workdir = _agent_workdir(
            other_user_config,
            other_user_config.agents[other_user_agent_index].name,
        )
        print(other_agent_credentials_endpoint)
        task = build_schedule_meeting_task(
            initiator_name=config.name,
            initiator_email=config.email,
            receiver_name=other_user_config.name,
            receiver_email=other_user_config.email,
        )
        agent.connect(other_agent_credentials_endpoint, task)
        run_finished_at = datetime.now(tz=timezone.utc)

        # Create test object
        test = MeetingScheduleTest(config)
        # Make sure what we wanted happened
        succeeded = test.success(other_user_config.name, other_user_config.email)
        oracle_details = test.last_evaluation or {
            "oracle": "schedule_meeting",
            "oracle_success": succeeded,
            "oracle_reason": "oracle_result_unavailable",
        }
        local_audit_records, execution_stats = collect_query_execution_stats(
            local_workdir=agent.workdir,
            peer_workdir=other_agent_workdir,
            started_at=run_started_at,
            finished_at=run_finished_at,
        )
        print("ScheduleMeetingOracle:", json.dumps(oracle_details, sort_keys=True))
        print("ExecutionStats:", json.dumps(execution_stats, sort_keys=True))
        record = build_experiment_result_record(
            task_name="schedule_meeting",
            mode=mode,
            config_path=config_path,
            other_config_path=other_user_config_path,
            agent_aid=agent.aid,
            peer_aid=other_agent_credentials_endpoint,
            runtime_auth_enabled=config.agents[agent_index].toy_runtime_auth is not None,
            success=succeeded,
            audit_records=local_audit_records,
            extra_fields={
                **oracle_details,
                **execution_stats,
            },
        )
        append_experiment_result_record("schedule_meeting", record)
        print("Success:", succeeded)



if __name__ == "__main__":
    # Get path to config file
    import sys
    mode = sys.argv[1]
    if mode not in ["listen", "query"]:
        raise ValueError("Mode (first argument) must be either 'listen' or 'query'")
    config_path = sys.argv[2]
    other_user_config_path = sys.argv[3] if len(sys.argv) > 3 else None
    
    if mode == "query" and other_user_config_path is None:
        raise ValueError("Endpoint (third argument) must be provided in query mode")
    main(mode=mode,
         config_path=config_path,
         other_user_config_path=other_user_config_path)
