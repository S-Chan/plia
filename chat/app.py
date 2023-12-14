import time
import uuid

import openai
import requests
import streamlit as st

client = openai.OpenAI()

MODEL = 'gpt-4-1106-preview'

st.set_page_config(page_title='Plio Chat Demo')

if 'session_id' not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())

if 'file_ids' in st.session_state:
    st.session_state.file_ids = []

if 'assistant' not in st.session_state:
    openai.api_key = st.secrets['OPENAI_API_KEY']
    st.session_state.assistant = openai.beta.assistants.retrieve(
        st.secrets['OPENAI_ASSISTANT']
    )
    st.session_state.thread = client.beta.threads.create(
        metadata={'session_id': st.session_state.session_id}
    )

if 'messages' not in st.session_state:
    st.session_state.messages = []

for message in reversed(st.session_state.messages):
    with st.chat_message(message.role):
        for content_part in message.content:
            st.write(content_part.text.value)

if prompt := st.chat_input('How can I help you?'):
    with st.chat_message('user'):
        st.write(prompt)

    message_data = {
        'thread_id': st.session_state.thread.id,
        'role': 'user',
        'content': prompt
    }
    if 'file_ids' in st.session_state:
        message_data['file_ids'] = st.session_state.file_ids

    st.session_state.messages.append(
        client.beta.threads.messages.create(**message_data)
    )

    st.session_state.run = client.beta.threads.runs.create(
        thread_id=st.session_state.thread.id,
        assistant_id=st.session_state.assistant.id,
    )
    # TODO: handle error states
    while st.session_state.run.status != 'completed':
        st.session_state.run = client.beta.threads.runs.retrieve(
            thread_id=st.session_state.thread.id,
            run_id=st.session_state.run.id,
        )
        if st.session_state.run.status == 'requires_action':
            tool_outputs = []
            for call in st.session_state.run.required_action.submit_tool_outputs.tool_calls:
                match call.function.name:
                    case 'GetIntegrations':
                        resp = requests.get('https://api.runplio.com/integrations')
                    case 'RunAWSIntegration':
                        resp = requests.post('https://api.runplio.com/integrations/aws')

                tool_outputs.append({
                    'tool_call_id': call.id,
                    'output': str(resp.json()),
                })
            st.session_state.run = client.beta.threads.runs.submit_tool_outputs(
                thread_id=st.session_state.thread.id,
                run_id=st.session_state.run.id,
                tool_outputs=tool_outputs,
            )

        time.sleep(1)

    st.session_state.messages = [
        m for m in
        client.beta.threads.messages.list(thread_id=st.session_state.thread.id)
    ]
    with st.chat_message('assistant'):
        for content_part in st.session_state.messages[0].content:
            st.markdown(content_part.text.value)
