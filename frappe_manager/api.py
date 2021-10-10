import base64, json
import datetime
import socket
import frappe
from xml.etree import ElementTree
import requests

"""
add domain
create site
certbot
"""

def get_server_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('8.8.8.8', 1))
	ip = s.getsockname()[0]
	s.close()

	frappe.db.set_value('Frappe Manager Settings', 'Frappe Manager Settings', 'server_ip', ip)

	return ip

def fetch(url):
    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/xml"
    try:
        #return make_get_request(url=url, headers=headers)
        return requests.get(url, headers=headers)

    except Exception as e:
        frappe.errprint("Something seems is wrong !!! \n \n" + e)

def get_all_domains():
    url, domains = get_existing_domains()
    records = []
    count = 0
    
    # move this to get domains? -- its from add_domain
    for child in domains[3][0]:
        record[count] = child.attrib.get("Name")
        count+=1

    frappe.errprint(records)

    return records



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
        frappe.errprint(response.content)

        # check if given domain exists
        if check_domain:
            if check_domain in str(response.content):
                return True

        return (url + post_command), xml
    else:
        return "", None

"""
get domains
add new one
send add domain request with old domains
"""
@frappe.whitelist()
def add_domain(lead_name):
    lead = frappe.get_cached_doc('Lead', lead_name )

    if (lead.site_domain and lead.site_domain != ""):
        settings = frappe.get_cached_doc('Frappe Manager Settings')
        ip = settings.server_ip or get_server_ip()
        base_url, response = get_existing_domains()

        if response:
            hosts = ""
            count = 1
            
            # format existing domains for posting
            for child in response[3][0]:
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
                str(count), lead.site_domain, "A", ip, "1000")

            post_url = base_url + hosts

        frappe.errprint("completed")

### adding a new host
# get host from lead -d
# add to hosts string -d
# send to server - d
# check and do not add existing domain - d
# frappe.errprint( get_existing_domains(check_domain=lead.site_domain) )