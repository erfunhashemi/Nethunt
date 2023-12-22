import requests

import socket

from ipwhois import IPWhois

from ping3 import ping

import subprocess

import sys

import time

from colorama import Fore, Style



def print_loader():

    for _ in range(3):

        sys.stdout.write("\rScanning" + "." * 3)

        sys.stdout.flush()

        time.sleep(1)

        sys.stdout.write("\rScanning" + " " * 3)

        sys.stdout.flush()

        time.sleep(1)



def colorize_text(text, color):

    return f"{color}{text}{Style.RESET_ALL}"



def check_website(url, ping_site=False, nmap_scan=False):

    # Check if the website is online

    try:

        response = requests.head(url, timeout=5)

        if response.status_code == 200:

            print(colorize_text(f"{url} is online", Fore.GREEN))

        else:

            print(colorize_text(f"{url} is offline", Fore.RED))

            # If the website is offline, continue with the next one

            return

    except requests.ConnectionError:

        print(colorize_text(f"{url} is offline", Fore.RED))

        # If the website is offline, continue with the next one

        return



    # Get the IP address of the website

    try:

        ip_address = socket.gethostbyname(url)

        print(colorize_text(f"IP address: {ip_address}", Fore.GREEN))



        # Get information about the IP address (location, host, etc.)

        try:

            ipwhois = IPWhois(ip_address)

            result = ipwhois.lookup_rdap()

            print(colorize_text(f"Location: {result['asn_description']}", Fore.GREEN))

            print(colorize_text(f"Host: {result['asn_registry']}", Fore.GREEN))

        except Exception as ipwhois_error:

            print(colorize_text(f"Error during IPWhois lookup: {ipwhois_error}", Fore.RED))

        

    except socket.gaierror:

        print(colorize_text("Unable to get IP address information.", Fore.RED))



    # Get domain information

    if "://" in url:

        url = url.split("://")[1]

    print(colorize_text(f"Domain: {url}", Fore.GREEN))



    # Ping the website

    if ping_site:

        try:

            rtt = ping(url)

            if rtt is not None:

                print(colorize_text(f"Ping RTT: {rtt:.2f} ms", Fore.GREEN))

            else:

                print(colorize_text("Unable to ping the site.", Fore.RED))

        except Exception as e:

            print(colorize_text(f"Error during ping: {e}", Fore.RED))



    # Perform Nmap scan for open ports (TCP and UDP)

    if nmap_scan:

        try:

            print_loader()

            command = f"nmap -p 1-65535 -T4 -A -sS -sU {url}"

            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)

            

            # Highlight opened ports in red

            result_text = result.stdout.replace("open", colorize_text("open", Fore.RED))



            print(colorize_text("\nNmap scan results:", Fore.GREEN))

            print(result_text)

        except Exception as e:

            print(colorize_text(f"Error during Nmap scan: {e}", Fore.RED))



# Example usage

website_url = input("Enter the website URL: ")

check_website(website_url, ping_site=True, nmap_scan=True)

