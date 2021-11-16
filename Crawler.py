#!/usr/bin/evn python

import requests

# url = "google.com"

def request(url):
    try:
        return requests.get("http://" + url)
    except requests.exceptions.ConnectionError:
        pass

target_url = "google.com"

# with open("subdomains-wodlist.list", "r") as wordlist_file:
with open("test-wordlist.list", "r") as wordlist_file:

    for line in wordlist_file:
        word = line.strip()
        test_url = word + "." + target_url
        response = request(test_url)
        if response:
            print("[+] Discorvered Subdomains ---> " + test_url)