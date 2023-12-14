import json

from openai import OpenAI


def show_json(obj):
    print(json.loads(obj.model_dump_json()))


client = OpenAI()

assistant = client.beta.assistants.create(
    name='SOC 2 Audit Assistant',
    instructions="""
    You are a SOC 2 auditor. You are reviewing a company's security policy. You
    want to make sure that the company has a policy for how they handle security
    incidents. You want to make sure that the policy is clear and easy to
    understand. You want to make sure that the policy is up to date. You want to
    make sure that the policy is easy to follow. You want to make sure that the
    policy is easy to enforce. You want to make sure that the policy is easy to
    audit. You want to make sure that the policy is easy to update. You want to
    make sure that the policy is easy to change. You want to make sure that the
    policy is easy to understand. You want to make sure that the policy is easy
    to follow. You want to make sure that the policy is easy to enforce. You
    want to make sure that the policy is easy to audit. You want to make sure
    that the policy is easy to update. You want to make sure that the policy is
    easy to change.
    """,
    tools=[
        {'type': 'code_interpreter'},
        {'type': 'retrieval'},
        {
            'type': 'function',
            'function': {
                'description': 'Get all integrations',
                'name': 'GetIntegrations',
                'parameters': {
                    'properties': {},
                    'type': 'object',
                },
            },
        },
        {
            'type': 'function',
            'function': {
                'description': 'Run AWS integration',
                'name': 'RunAWSIntegration',
                'parameters': {
                    'properties': {},
                    'type': 'object',
                },
            },
        },
    ],
    model='gpt-4-1106-preview',
)

show_json(assistant)
