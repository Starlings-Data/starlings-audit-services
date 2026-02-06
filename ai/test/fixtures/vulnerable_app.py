# Intentionally vulnerable Python file for scanner testing
# DO NOT use this code in production!

import openai
from flask import Flask, request

app = Flask(__name__)

# KEY-001: Hardcoded OpenAI API key
OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
client = openai.OpenAI(api_key=OPENAI_API_KEY)

# KEY-002: Hardcoded Anthropic API key
ANTHROPIC_API_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJK"

# KEY-003: Generic secret
DATABASE_URL = "postgresql://admin:supersecretpassword123@db.example.com:5432/mydb"
SECRET_KEY = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"

# INJ-001: f-string prompt injection
@app.route("/chat", methods=["POST"])
def chat():
    user_input = request.json.get("message")
    prompt = f"You are a helpful assistant. The user says: {user_input}. Please respond helpfully."
    response = client.chat.completions.create(
        model="gpt-3.5-turbo-0301",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

# INJ-002: String concatenation in prompt
@app.route("/ask", methods=["POST"])
def ask():
    user_query = request.json.get("query")
    prompt = "Answer the following question: " + user_query
    response = client.chat.completions.create(
        model="text-davinci-003",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

# INJ-003: Unvalidated input directly to API
@app.route("/complete", methods=["POST"])
def complete():
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": request.json.get("prompt")}]
    )
    return response.choices[0].message.content

# CFG-003: SSL verification disabled
import requests
resp = requests.post("https://api.openai.com/v1/chat/completions",
                     verify=False,
                     headers={"Authorization": f"Bearer {OPENAI_API_KEY}"})

if __name__ == "__main__":
    app.run(debug=True)
