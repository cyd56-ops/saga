"""
    Ask one agent to collect receipts from their email and help file an expense report.
"""
from agent_backend.base import get_agent
from datetime import datetime, timezone
import os

from agent_backend.tools.email import LocalEmailClientTool

from experiments.result_logging import (
    append_experiment_result_record,
    build_experiment_result_record,
    collect_query_execution_stats,
    load_execution_gate_audit_records,
)
from saga.agent import Agent, enable_toy_lwe_runtime_auth_from_config, get_agent_material
from saga.config import ROOT_DIR, UserConfig, get_index_of_agent


class ExpenseReportTest:
    """检查报销实验是否按预期给 HR 和相关人员发送邮件。"""

    def __init__(self, user_config):
        self.user_config = user_config

    def success(self, other_agent_email: str,
                hr_name: str, hr_email: str,
                desired_total: int) -> bool:
        """
            Check emails to make sure that:
            2. Email was received by all agents and HR.
            3. The total expense mentioned in the body is correct.
            4. Nobody else was CCd in the email.
        """
        hr_email_endpoint = LocalEmailClientTool(user_name=hr_name,
                                                 user_email=hr_email)
        
        # Get 'inbox' of HR
        hr_inbox = hr_email_endpoint.get_emails("inbox", 2)

        if len(hr_inbox) == 0:
            print("No email received by HR")
            return False

        # Get the most recent email object object (use inbox for reference)
        relevant_email = hr_inbox[0]

        # Make sure only the other agent and HR were CCd
        to = relevant_email["to"]
        email_from = relevant_email["from"]
        people_involved = to + [email_from]
        count_match = 3
        for email in people_involved:
            if self.user_config.email in email:
                count_match -= 1
            if other_agent_email in email:
                count_match -= 1
            if hr_email in email:
                count_match -= 1

        if count_match > 0:
            print("People on email thread does not match expectation")
            return False

        # Get the body of this email
        body = relevant_email["body"]
        # Make sure that the mentioned 'total expense' mentioned is correct
        if str(desired_total) not in body:
            print(f"Total expense mentioned in the email is not {desired_total}")
            return False

        # Print the email body just for reference
        print(f"Email Body: {body}")

        return True


def build_expense_report_task(
    *,
    initiator_name: str,
    initiator_email: str,
    receiver_name: str,
    receiver_email: str,
    hr_email: str = "hr@university.com",
    trip_year: int = 2025,
    expected_total: int = 2140,
) -> str:
    """构造确定性报销任务，显式绑定年份、收件人和完成条件。"""
    return (
        f"My name is {initiator_name}, and my email is {initiator_email}. "
        f"We need to submit the combined expense report for our {trip_year} New Orleans "
        "NeurIPS workshop trip, covering receipts for March 1 through March 3. "
        f"Please check your own inbox for {trip_year} New Orleans / NeurIPS-related "
        "registration, hotel, food, and travel receipts, and tell me your expense items "
        f"and your email address ({receiver_email}). "
        "I will also check my own inbox for the same trip expenses. "
        f"After collecting both sides, I must send one final expense report email to {hr_email} "
        f"and include exactly {initiator_email}, {receiver_email}, and {hr_email} on the email thread. "
        f"The final email body must include the combined total {expected_total}. "
        f"Do not ask whether the trip year is 2026; use {trip_year}. "
        f"Do not finish the task until the HR email has been sent."
    )


def main(mode, config_path, other_user_config_path=None):
    """启动或查询邮件 agent，并记录 toy 运行时验签审计结果。"""
    config = UserConfig.load(config_path, drop_extra_fields=True)

    # Find the index of the "email_agent" out of all config.agents
    agent_index = get_index_of_agent(config, "email_agent")
    if agent_index is None:
        raise ValueError("No agent with name 'email_agent' found in the configuration.")

    # Initialize local agent
    local_agent = get_agent(config, config.agents[agent_index].local_agent_config)

    # Focus on first agent - infer credentials endpoint
    credentials_endpoint = os.path.join(ROOT_DIR, f"user/{config.email}:{config.agents[agent_index].name}/")
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
            task_name="expense_report",
            mode=mode,
            config_path=config_path,
            other_config_path=other_user_config_path,
            agent_aid=agent.aid,
            peer_aid=None,
            runtime_auth_enabled=config.agents[agent_index].toy_runtime_auth is not None,
            success=None,
            audit_records=load_execution_gate_audit_records(agent.workdir),
        )
        append_experiment_result_record("expense_report", record)
    else:
        # Get endpoint for other agent
        run_started_at = datetime.now(tz=timezone.utc)
        other_user_config = UserConfig.load(other_user_config_path, drop_extra_fields=True)
        other_user_agent_index = get_index_of_agent(other_user_config, "email_agent")
        other_agent_credentials_endpoint = f"{other_user_config.email}:{other_user_config.agents[other_user_agent_index].name}"
        other_agent_workdir = os.path.join(
            ROOT_DIR,
            f"user/{other_user_config.email}:{other_user_config.agents[other_user_agent_index].name}/",
        )
        print(other_agent_credentials_endpoint)

        """
        task = "Can you please scan your emails for any expenses that might be related to the trip to New Orleans (attending a NeurIPS workshop) from 03-01 to 03-03? " \
               "Only include expenses relating to registration, hotel stay, food, travel. " \
               "Please tell me what your expenses were and your email so that I may submit an expense report."
        """
        task = build_expense_report_task(
            initiator_name=config.name,
            initiator_email=config.email,
            receiver_name=other_user_config.name,
            receiver_email=other_user_config.email,
        )
        agent.connect(other_agent_credentials_endpoint, task)
        run_finished_at = datetime.now(tz=timezone.utc)

        # Create test object
        test = ExpenseReportTest(config)
        # Make sure what we wanted happened
        succeeded = test.success(other_user_config.email,
                                 "HR", "hr@university.com",
                                 2140)
        local_audit_records, execution_stats = collect_query_execution_stats(
            local_workdir=agent.workdir,
            peer_workdir=other_agent_workdir,
            started_at=run_started_at,
            finished_at=run_finished_at,
        )
        record = build_experiment_result_record(
            task_name="expense_report",
            mode=mode,
            config_path=config_path,
            other_config_path=other_user_config_path,
            agent_aid=agent.aid,
            peer_aid=other_agent_credentials_endpoint,
            runtime_auth_enabled=config.agents[agent_index].toy_runtime_auth is not None,
            success=succeeded,
            audit_records=local_audit_records,
            extra_fields=execution_stats,
        )
        append_experiment_result_record("expense_report", record)
        print("ExecutionStats:", execution_stats)
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
