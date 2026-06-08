"""
    Ask one agent to collaborate and help write a blogpost together.
"""
from agent_backend.base import get_agent
from datetime import datetime, timezone
import os

from agent_backend.tools.documents import LocalDocumentsTool

from experiments.result_logging import (
    append_experiment_result_record,
    build_experiment_result_record,
    collect_query_execution_stats,
    load_execution_gate_audit_records,
)
from saga.agent import Agent, enable_toy_lwe_runtime_auth_from_config, get_agent_material
from saga.config import ROOT_DIR, UserConfig, get_index_of_agent


class BlogPostTest:
    """检查协作写作实验是否生成了预期博客文档。"""

    def __init__(self, user_config):
        self.user_config = user_config

    def success(self, other_agent_email, blogpost_name) -> bool:
        """
            Check if the blogpost was:
            1. One of them created and stored in their files.
        """
        self_documents = LocalDocumentsTool(user_email= self.user_config.email)
        other_documents = LocalDocumentsTool(user_email=other_agent_email)
        
        # TODO- make sure nobody else was invited to the meeting
        files_self = self_documents.search_by_query(blogpost_name)
        files_other = other_documents.search_by_query(blogpost_name)

        if len(files_self) == 0 and len(files_other) == 0:
            print("None of them saved!")
            return False
        
        doc_focus = files_self[0] if len(files_self) > 0 else files_other[0]

        # Check if the blogpost has the same title and content
        if blogpost_name not in doc_focus["filename"]:
            print("Blogpost title not what was expected")
            return False

        return True


def build_blogpost_task(
    *,
    initiator_name: str,
    initiator_email: str,
    receiver_name: str,
    receiver_email: str,
    blogpost_filename: str = "Privacy in the Age of AI: Legal and Ethical Implications.md",
) -> str:
    """构造确定性的协作写作任务，显式绑定最终保存文件名。"""
    return (
        f"My name is {initiator_name}, and my email is {initiator_email}. "
        f"We are collaborating with {receiver_name} ({receiver_email}) to write a markdown blogpost "
        "about the implications of privacy in the context of AI. "
        "Please handle the final artifact on your side now: draft a concise 600-900 word markdown post "
        "that combines legal/ethical privacy analysis with an ML perspective. "
        "Do not search existing blogposts or wait for another round of drafting. "
        "Save the final markdown file in documents as "
        f"'{blogpost_filename}'. "
        "The saved file must be the final deliverable. "
        f"Do not finish the task until the blogpost has been saved under '{blogpost_filename}'. "
        "After saving, reply only with the task-finished token."
    )


def main(mode, config_path, other_user_config_path=None):
    """启动或查询写作 agent，并记录 toy 运行时验签审计结果。"""
    config = UserConfig.load(config_path, drop_extra_fields=True)

    # Find the index of the "writing_agent" out of all config.agents
    agent_index = get_index_of_agent(config, "writing_agent")
    if agent_index is None:
        raise ValueError("No agent with name 'writing_agent' found in the configuration.")

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
            task_name="create_blogpost",
            mode=mode,
            config_path=config_path,
            other_config_path=other_user_config_path,
            agent_aid=agent.aid,
            peer_aid=None,
            runtime_auth_enabled=config.agents[agent_index].toy_runtime_auth is not None,
            success=None,
            audit_records=load_execution_gate_audit_records(agent.workdir),
        )
        append_experiment_result_record("create_blogpost", record)
    else:
        # Get endpoint for other agent
        run_started_at = datetime.now(tz=timezone.utc)
        other_user_config = UserConfig.load(other_user_config_path, drop_extra_fields=True)
        other_user_agent_index = get_index_of_agent(other_user_config, "writing_agent")
        other_agent_credentials_endpoint = f"{other_user_config.email}:{other_user_config.agents[other_user_agent_index].name}"
        other_agent_workdir = os.path.join(
            ROOT_DIR,
            f"user/{other_user_config.email}:{other_user_config.agents[other_user_agent_index].name}/",
        )
        print(other_agent_credentials_endpoint)
        task = build_blogpost_task(
            initiator_name=config.name,
            initiator_email=config.email,
            receiver_name=other_user_config.name,
            receiver_email=other_user_config.email,
        )
        agent.connect(other_agent_credentials_endpoint, task)
        run_finished_at = datetime.now(tz=timezone.utc)

        # Create test object
        test = BlogPostTest(config)
        # Make sure what we wanted happened
        succeeded = test.success(other_user_config.email,
                                 blogpost_name="Privacy in the Age of AI")
        local_audit_records, execution_stats = collect_query_execution_stats(
            local_workdir=agent.workdir,
            peer_workdir=other_agent_workdir,
            started_at=run_started_at,
            finished_at=run_finished_at,
        )
        record = build_experiment_result_record(
            task_name="create_blogpost",
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
        append_experiment_result_record("create_blogpost", record)
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
