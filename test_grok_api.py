import requests
import json
import sys
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

api_key = "xai-V6egRq6VEohNCFwfVIzu0bsWAR0SCXaoV6CRRk2LFNLuHLohBTPe5LxJmWVT3AKzPTdGsTq7m3g5YiVH"
url = "https://api.x.ai/v1/chat/completions"
headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

def query_grok(prompt, model="grok-beta", max_tokens=1000):
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        result = response.json()
        logging.info("Success! Response received.")
        return result["choices"][0]["message"]["content"]
    except requests.exceptions.RequestException as e:
        logging.error(f"API Error - Status: {e.response.status_code if e.response else 'N/A'}, Text: {e.response.text if e.response else str(e)}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 test_grok_api.py \"your prompt here\"")
        sys.exit(1)
    prompt = sys.argv[1]
    response = query_grok(prompt)
    if response:
        print("Grok Response:")
        print(response)
        with open("grok_response.txt", "a") as f:
            f.write(f"Prompt: {prompt}\nResponse: {response}\n\n")
