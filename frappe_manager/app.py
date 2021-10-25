import base64, json
import datetime
import socket
import random
from xml.etree import ElementTree
import requests
from requests.structures import CaseInsensitiveDict

# bench-manager

import os
import re
import shlex
import time
import subprocess
from subprocess import PIPE, STDOUT, Popen, check_output

import frappe
from frappe import _
from datetime import datetime

"""
Package everything including fixtures

Customised Doctypes to add to fixtures
- Site fields
- Lead field
- Custom script?
- Web Page

v2
- update lead or put error and / OR alert tech support notify_admins()-> after creating site 
- billing
- # site name creation algo --> do in js
- ## business name split by space, do not allow arabic
- ## array in lower case, add another element, add pos, add nums
"""


# Email client
## get and email lead
## copy template

def email_client(site, method=None):
    """send mail with login details"""
    
    lead = frappe.get_doc('Lead', site.lead)

    site_url = "https://" + site.name + "/login"
    from frappe.utils.user import get_user_fullname

    subject = "Welcome to QPOS 🎉"
    template = "new_company"

    created_by = get_user_fullname(frappe.session['user'])
    if created_by == "Guest":
        created_by = "Administrator"

    args = {
        'name': lead.lead_name,
        'user': "Administrator",
        'password': site.site_admin_password,
        'title': subject,
        'login_url': site_url,
        'link': site_url,
        'site_url': site.name,
        'created_by': created_by
    }

    sender = frappe.session.user not in frappe.core.doctype.user.user.get_formatted_email(frappe.session.user) or None

    frappe.sendmail(recipients=lead.email_id, sender=sender, subject=subject,
        template=template, args=args, header=[subject, "green"],
        delayed=None, retry=3)


def _refresh(doctype, docname, commands):
    frappe.get_doc(doctype, docname).run_method("after_command", commands=commands)


def safe_decode(string, encoding="utf-8"):
	try:
		string = string.decode(encoding)
	except Exception:
		pass
	return string


def get_installed_apps(site_name):
        all_sites = safe_decode(check_output("ls")).strip("\n").split("\n")

        retry = 0
        while site_name not in all_sites and retry < 3:
            time.sleep(2)
            print("waiting for site creation...")
            retry += 1
            all_sites = safe_decode(check_output("ls")).strip("\n").split("\n")

        if retry == 3 and site_name not in all_sites:
            list_apps = "frappe"
        else:
            list_apps = check_output(
                shlex.split("bench --site {site_name} list-apps".format(site_name=site_name)),
                cwd="..",
            )

        if "frappe" not in safe_decode(list_apps):
            list_apps = "frappe"
        return safe_decode(list_apps).strip("\n").split("\n")


# setup site
@frappe.whitelist()
def add_site(lead, method=None):
    
    if type(lead) is str:
        lead = frappe.get_cached_doc('Lead', lead)

    if (lead.site_domain and lead.site_domain != ""):
        settings = frappe.get_cached_doc('Frappe Manager Settings')
        ip = settings.server_ip or get_server_ip()

        # get_domains()
        base_url, response = get_existing_domains()

        # add_domain() 
        if response: #else should report an issue
            add_domain(lead.site_domain, response, base_url, ip) # refactor get_ex_doms() -> bring attributes to add_site
        
        # create_site()
        site_name = lead.site_domain +"."+ settings.domain
        install_erpnext = "true"
        mysql_password = settings.frappe_database_password
        
        # Make strong passwords from client data - add to settings #Lname initial + fname + Month + day + random char
        person_name = lead.lead_name.split(" ")
        domain_part = lead.site_domain[1:3]
        day = str(datetime.now().day)
        month = str(datetime.now().month)

        chars = random.choices(['*', "!", '(', ')'], k=2)
        site_admin_password = "QP" + person_name[0][0] + person_name[1][0] + str(domain_part) + day + month + chars[0] + chars[1]
        
        key = lead.site_domain
        
        create_site(site_name, install_erpnext, mysql_password, site_admin_password, lead.name, key)

        return True

        # get_installed_apps(site_name)
        # all_domains = get_all_domains() # return all_domains

        # frappe.errprint(all_domains)
        # update lead or put error and/ OR alert tech support notify_admins() 


# implement this directly from bench-mgr
# update lead status
@frappe.whitelist()
def create_site(site_name, install_erpnext, mysql_password, admin_password, leadname, key):
    
    commands = [
        "bench new-site --mariadb-root-password {mysql_password} --admin-password {admin_password} --no-mariadb-socket {site_name}".format(
            site_name=site_name, admin_password=admin_password, mysql_password=mysql_password
        )
    ]
    app_list = ""
    if install_erpnext == "true":
        with open("./apps.txt", "r") as f:
            app_list = f.read()
        if "erpnext" not in app_list:
            commands.append("bench get-app erpnext")
        commands.append(
            "bench --site {site_name} install-app erpnext".format(site_name=site_name)
        )
        commands.append(
            "bench --site {site_name} install-app saudi_pos".format(site_name=site_name)
        )
        commands.append(
            "bench --site {site_name} migrate".format(site_name=site_name)
        )
        commands.append(
            "bench setup nginx --yes"
        )
    
    frappe.enqueue(
        "bench_manager.bench_manager.utils.run_command",
        commands=commands,
        doctype="Bench Settings",
        key=key,
    )
    all_sites = safe_decode(check_output("ls")).strip("\n").split("\n")
    if site_name not in all_sites:
        time.sleep(2)
        all_sites = safe_decode(check_output("ls")).strip("\n").split("\n")
    
    doc = frappe.get_doc({  # why pass "app_list" as frappe? 
        "doctype": "Site", 
        "site_name": site_name, 
        "app_list": "frappe", 
        "site_admin_password": admin_password, 
        "lead": leadname, 
        "automatically_created": 1,
        "developer_flag": 1 
    })
    doc.insert()
    #frappe.db.commit()
    return "completed"


# adds new domain to current ones
# adds new one
# sends new list to the registrar
def add_domain(new_domain, existing_domains, base_url, ip): 
    # add new_domain validation in js  
    hosts = ""
    count = 1
    
    # format existing domains for posting
    for child in existing_domains[3][0]:
        hosts += "&HostName{0}={1}&RecordType{0}={2}&Address{0}={3}&TTL{0}={4}".format(
            str(count),
            child.attrib.get("Name"),
            child.attrib.get("Type"),
            child.attrib.get("Address"),
            child.attrib.get("TTL")
        )
        count+=1
    
    # add new domain to existing domains
    hosts += "&HostName{0}={1}&RecordType{0}={2}&Address{0}={3}&TTL{0}={4}".format(
        str(count), new_domain, "A", ip, "1000")

    post_url = base_url + hosts
    
    response = fetch(post_url)
    
    # add error handling
    if response.status_code == 200:
        return [ str(response.content) ]


def get_server_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))
    ip = s.getsockname()[0]
    s.close()

    frappe.db.set_value('Frappe Manager Settings', 'Frappe Manager Settings', 'server_ip', ip)

    return ip

def fetch(url): # error handling here, anything outside the accepted response
    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/xml"
    try:
        return requests.get(url, headers=headers)

    except Exception as e:
        frappe.errprint("Something seems is wrong !!! \n \n" + e)


@frappe.whitelist(allow_guest=True)
def get_all_domains():
    url, domains = get_existing_domains()
    records = []

    for child in domains[3][0]:
        records.append(child.attrib.get("Name"))

    return records


### gets current domains
def get_existing_domains(check_domain=None):
    settings = frappe.get_cached_doc('Frappe Manager Settings')

    ip = settings.server_ip or get_server_ip()

    domain_parts = settings.domain.split(".")
    domain = "&SLD={}&TLD={}".format(domain_parts[0], domain_parts[1])

    credentials = "ApiUser={}&ApiKey={}&UserName={}&ClientIp={}".format(settings.username, settings.api_key, settings.username, ip)
    get_command = "&Command=namecheap.domains.dns.getHosts";
    post_command = "&Command=namecheap.domains.dns.setHosts"
    base_url = ""

    if settings.testing == 1:
        base_url = "https://api.sandbox.namecheap.com/xml.response?"
    else:
        base_url = "https://api.namecheap.com/xml.response?"

    url = base_url + credentials + domain

    response = fetch(url + get_command)

    if response.status_code == 200:
        xml = ElementTree.fromstring(response.content)
        #frappe.errprint(response.content)

        # check if given domain exists
        if check_domain:
            if check_domain in str(response.content):
                return True

        return (url + post_command), xml
    else:
        return "", None
