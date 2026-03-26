import spf
import re

def extrahiere_absender_ip(headers):
    
    received_headers = [
        h["value"] for h in headers if h["name"].lower() == "received"
    ]

    #Von unten nach oben also die erste ip von unten diese brauche ich
    for header in reversed(received_headers):
        #Ip Adresse auf dem Header extrahieren
        #IPv4
        match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
        if match:
            return match.group(1) #Reine IP ohne die Klammer

        # IPv6
        match = re.search(r'\[([0-9a-fA-F:]+)\]', header)
        if match:
            return match.group(1)


    return None

def extrahiere_return_path(headers):
    #Ich hole mir nur das erste Ergebnis, falls keines vorhanden ist einfach leeren String ausgeben
    return_path = next(
            (h["value"] for h in headers if h["name"].lower() == "return-path"),
            ""
    ) 

    match = re.search(r'<(.+?)>', return_path)
    if match:
        return match.group(1) #Wieder die reine IP Adresse, also ohne die Klammern
    return return_path   



def check_spf(headers): 
    ip = extrahiere_absender_ip(headers) #Der Server der die Mail geschickt hat
    absender = extrahiere_return_path(headers) #Die Adresse die beim SMTP angegeben wurde

    if not ip or not absender:
        return "none", "Konnte IP oder Absender nicht extrahieren"

    domain = absender.split("@")[-1] 

    #SPF check
    result, explanation = spf.check2(
        i = ip,
        s = absender,
        h = domain

    )

    return result, explanation