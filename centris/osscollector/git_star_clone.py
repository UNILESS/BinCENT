import requests
import json

# Your GitHub token
token = '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'

# The headers for the API request
headers = {
    'Authorization': f'token {token}'
}

# List to store the URLs of top repositories
top_repos = []

# Because GitHub only returns a maximum of 100 results per API call, you have to paginate through results
for i in range(20):  # Change the range to 20
    # Construct the API URL
    url = f"https://api.github.com/search/repositories?q=language:C&sort=stars&order=desc&page={i + 1}&per_page=100"

    # Make the API request
    response = requests.get(url, headers=headers)  # Pass the headers

    # If the request was successful
    if response.status_code == 200:
        # Load the JSON data from the response
        data = json.loads(response.text)

        # For each repository in the data
        for repo in data['items']:
            # Add the repository's URL to the list
            top_repos.append(repo['html_url'])

            # If we've collected 2000 repositories, stop collecting
            if len(top_repos) >= 2000:  # Change the number to 2000
                break

    # If the request was not successful, print the status code and message
    else:
        print(f"Failed with status {response.status_code}: {response.text}")
        break

# Write the URLs of the top repositories into a text file
with open('top_repos.txt', 'w') as f:
    for i, repo in enumerate(top_repos, 1):
        f.write(f"git clone {repo}\n")
