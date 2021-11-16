#!/usr/bin/evn python

import scaner


target_url = input("Enter your target url")
data_dict = {"username": "", "password": "", "login": "submit"}
links_to_ignore = ["Your links to ignore."]

vuln_scanner = scaner.Scaner(target_url, links_to_ignore)
vuln_scanner.session.post(target_url, data=data_dict)
vuln_scanner.crawl()
