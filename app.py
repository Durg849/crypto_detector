from openai import OpenAI
client = OpenAI(api_key="YOUR_API_KEY")

response = client.chat.completions.create(
    model="gpt-3.5-turbo",
    messages=[{"role":"user", "content":"Hello world"}]
)
print(response.choices[0].message.content)