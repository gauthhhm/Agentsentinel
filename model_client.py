"""
model_client.py

A small helper for talking to a local Ollama server.

Setup:
    1. pip install requests python-dotenv
    2. Create a file named `.env` next to this script containing:
           OLLAMA_URL=http://localhost:11434
           MODEL_TAG=llama3
       (use whatever model you have pulled with `ollama pull ...`)
"""

import os

import requests
from dotenv import load_dotenv

# Read the .env file and put its values into the environment,
# so os.getenv() below can find them.
load_dotenv()

OLLAMA_URL = os.getenv("OLLAMA_URL")
MODEL_TAG = os.getenv("MODEL_TAG")

# How long (in seconds) we wait for Ollama to answer before giving up.
TIMEOUT_SECONDS = 120


def query_model(system_prompt: str, user_prompt: str) -> str:
    """
    Send a system prompt and a user prompt to Ollama and return the reply text.

    system_prompt: instructions that set the model's behaviour/role.
    user_prompt:   the actual question or task.

    Raises RuntimeError with a clear message if anything goes wrong.
    """
    # Fail early if the .env file is missing or incomplete.
    if not OLLAMA_URL:
        raise RuntimeError("OLLAMA_URL is not set. Add it to your .env file.")
    if not MODEL_TAG:
        raise RuntimeError("MODEL_TAG is not set. Add it to your .env file.")

    # rstrip("/") avoids a double slash if the URL ends with "/".
    url = f"{OLLAMA_URL.rstrip('/')}/api/chat"

    # The request body Ollama expects.
    payload = {
        "model": MODEL_TAG,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,  # get the whole answer at once, not piece by piece
    }

    try:
        response = requests.post(url, json=payload, timeout=TIMEOUT_SECONDS)
        # Turns HTTP errors (404, 500, ...) into exceptions.
        response.raise_for_status()
    except requests.exceptions.Timeout:
        raise RuntimeError(
            f"Request to {url} timed out after {TIMEOUT_SECONDS} seconds."
        )
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            f"Could not connect to Ollama at {url}. Is the server running?"
        )
    except requests.exceptions.HTTPError as e:
        raise RuntimeError(
            f"Ollama returned an HTTP error: {e} | Body: {response.text}"
        )
    except requests.exceptions.RequestException as e:
        # Catch-all for any other requests problem.
        raise RuntimeError(f"Unexpected request error: {e}")

    # Convert the response body from JSON text into a Python dict.
    try:
        data = response.json()
    except ValueError:
        raise RuntimeError(f"Response was not valid JSON: {response.text[:200]}")

    # Pull out data["message"]["content"], checking each step exists.
    message = data.get("message") if isinstance(data, dict) else None
    content = message.get("content") if isinstance(message, dict) else None

    if not content:
        raise RuntimeError(f"Response is missing message content: {data}")

    return content


# This block only runs when you execute `python model_client.py` directly,
# not when another file imports query_model.
if __name__ == "__main__":
    try:
        answer = query_model(
            system_prompt="You are a helpful assistant. Keep answers short.",
            user_prompt="What is the capital of France?",
        )
        print("Model answer:", answer)
    except RuntimeError as err:
        print("Error:", err)