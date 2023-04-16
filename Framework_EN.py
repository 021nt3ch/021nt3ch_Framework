import webbrowser 

print("SELECT OSINT CATEGORY: ")
print("1.  Frameworks")
print("2.  IP OSINT")
print("3.  Phone number OSINT")
print("4.  Email OSINT")
print("5.  Username OSINT")
print("6.  Business OSINT")
print("7.  Domain/URL OSINT")
print("8.  Image search OSINT")
print("9.  Steganography OSINT")
print("10. OSINT dojo attack surfaces and resources")
print("11. Search Engines")
print("12. Codes/Cypher ")
print("13. Market/Currencies")
print("14. Transport OSINT")
print("15. CTF Games")


category = input("SELECT OSINT CATEGORY NUMBER: ")

if category == "1":

    print("SELECT TOOL: ")
    print("1. OSINT framework")
    print("2. OSINT.sh")
    print("3. Security for everyone")
    print("4. OSINT tools")
    print("5. OSINT combine")
    print("6. Lampyre")
    print("7. Osintgeek")

    tool = input("SELECT TOOL NUMBER: ")
    if tool == "1":
        webbrowser.open("https://osintframework.com/")
    elif tool == "2":
        webbrowser.open("https://osint.sh/")    
    elif tool == "3":
        webbrowser.open("https://securityforeveryone.com/tools/free-security-tools") 
    elif tool == "4":
        webbrowser.open("https://www.osinttechniques.com/osint-tools.html")
    elif tool == "5":
        webbrowser.open("https://www.osintcombine.com/tools")
    elif tool == "6":
        webbrowser.open("https://lampyre.io/")
    elif tool == "7":
        webbrowser.open("https://osintgeek.de/tools")
    else:
        print("Non valid tool. EXIT ")
        exit()

elif category == "2":

    print("SELECT TOOL: ")
    print("1.  NordVPN ")
    print("2.  Hackertarget")
    print("3.  AbuseIP")
    print("4.  IPInfo")
    print("5.  InfoByIP")
    print("6.  MXtoolbox")
    print("7.  WhatsMyIP")
    print("8.  Whois Domaintools")
    print("9.  Grabify (IP logger)")
    print("10. IPlogger")

    tool = input("SELECT TOOL NUMBER: ")  
    if tool =="1":
        webbrowser.open("https://nordvpn.com/es/ip-lookup/")   
    elif tool == "2":
        webbrowser.open("https://hackertarget.com/geoip-ip-location-lookup/")     
    elif tool == "3":
        webbrowser.open("https://www.abuseipdb.com/")
    elif tool == "4":
        webbrowser.open("https://ipinfo.io/")
    elif tool == "5":
        webbrowser.open("https://www.infobyip.com/")
    elif tool == "6":
        webbrowser.open("https://mxtoolbox.com/ReverseLookup.aspx")
    elif tool == "7":
        webbrowser.open("https://whatismyipaddress.com/")
    elif tool == "8.":
        webbrowser.open("https://whois.domaintools.com/")
    elif tool == "9":
        webbrowser.open("https://grabify.link/")
    elif tool == "10":
        webbrowser.open("https://iplogger.org/")
    else:
        print("Non valid tool. EXIT ")
        exit()


elif category == "3":

    print("SELECT TOOL: ")
    print("1. Spy dialer ")
    print("2. Numlookup")
    print("3. Countrycode.org")
    print("4. Spokeo reverse phone lookup")
    print("5. TrueCaller")

    tool = input("SELECT TOOL NUMBER: ") 
    if tool == "1":
        webbrowser.open("https://www.spydialer.com/")
    elif tool == "2":
        webbrowser.open("https://www.numlookup.com/")
    elif tool == "3":
        webbrowser.open("https://countrycode.org/")
    elif tool == "4":
        webbrowser.open("https://www.spokeo.com/reverse-phone-lookup")
    elif tool == "5":
        webbrowser.open("https://www.truecaller.com/reverse-phone-number-lookup")
    else:
        print("Non valid tool. EXIT ")
        exit()

elif category == "4":

    print("SELECT TOOL: ")
    print("1.  EPIEOS ")
    print("2.  HUNTER.io ")
    print("3.  Infotracer")
    print("4.  SpokeO")
    print("5.  Anymailfinder")
    print("6.  Proofy")
    print("7.  Centralops")
    print("8.  Recordsfinder")
    print("9.  Rocketreach")
    print("10. Thatsthem")

    tool = input("SELECT TOOL NUMBER: ")
    if tool == "1":
        webbrowser.open("https://epieos.com/")
    elif tool == "2":
        webbrowser.open("https://hunter.io/")    
    elif tool == "3":
        webbrowser.open("https://infotracer.com/email-lookup/")
    elif tool == "4":
        webbrowser.open("https://www.spokeo.com/email-search")
    elif tool == "5":
        webbrowser.open("https://anymailfinder.com/")
    elif tool == "6":
        webbrowser.open("https://proofy.io/")
    elif tool == "7":
        webbrowser.open("https://centralops.net/co/emaildossier.aspx")
    elif tool == "8":
        webbrowser.open("https://recordsfinder.com/email/")
    elif tool == "9":
        webbrowser.open("https://rocketreach.co/")
    elif tool == "10":
        webbrowser.open("https://thatsthem.com/reverse-email-lookup")
    else:
        print("Non valid tool. EXIT ")
        exit()

elif category == "5":

    print("SELECT TOOL: ")
    print("1. SpokeO ")
    print("2. Whatsmyname ")
    print("3. InstantUsername")
    print("4. Osintcombine (TikTok search)")
    print("5. Osintcombine (Instagram Explorer)")

    tool = input("SELECT TOOL NUMBER: ")
    if tool == "1":
        webbrowser.open("https://www.spokeo.com/")
    elif tool == "2":
        webbrowser.open("https://whatsmyname.app/")
    elif tool == "3":
        webbrowser.open("https://instantusername.com/#/")
    elif tool == "4":
        webbrowser.open("https://www.osintcombine.com/tiktok-quick-search")
    elif tool == "5":
        webbrowser.open("https://www.osintcombine.com/instagram-explorer")
    else:
        print("Non valid tool. EXIT ")
        exit()
    

elif category == "6":

    print("SELECT TOOL: ")
    print("1. InfoClipper ")
    print("2. SystemDay ")
    print("3. E-justice portal")
    print("4. UK Companies house")
    print("5. Einforma (Spain)")

    tool = input("SELECT TOOL NUMBER: ")
    if tool == "1":
        webbrowser.open("https://www.info-clipper.com/en/")
    elif tool == "2":
        webbrowser.open("https://www.systemday.com/company-searches/")
    elif tool == "3":
        webbrowser.open("https://e-justice.europa.eu/")
    elif tool == "4":
        webbrowser.open("https://www.gov.uk/government/organisations/companies-house")
    elif tool == "5":
        webbrowser.open("https://www.einforma.com/buscador-empresas")
    else:
        print("Non valid tool. EXIT ")
        exit()

elif category == "7":

    print("SELECT TOOL: ")
    print("1. Domain Toolbox")
    print("2. Whois lookup ")
    print("3. Virustotal")
    print("4. URLExpander")
    print("5. ExpandURL")

    tool = input("SELECT TOOL NUMBER")
    if tool == "1":
        webbrowser.open("https://cipher387.github.io/domain_investigation_toolbox/")
    elif tool == "2":
        webbrowser.open("https://who.is/")
    elif tool == "3":
        webbrowser.open("https://www.virustotal.com/gui/home/upload")
    elif tool == "4":
        webbrowser.open("https://urlex.org/")
    elif tool == "5":
        webbrowser.open("https://www.expandurl.net/expand")
    else:
        print("Non valid tool. EXIT ")
        exit()


elif category == "8":
    print("SELECT TOOL: ")
    print("1. Tineye")
    print("2. Dupli-checker")
    print("3. Pimeyes")
    print("4. Smallseotools")
    print("5. Imgreverse")
    print("6. Reverseimage")
    print("7. Verexif (EXIF data)")

    tool = input("SELECT TOOL NUMBER: ")
    if tool == "1":
        webbrowser.open("https://tineye.com/")
    elif tool == "2":
        webbrowser.open("https://www.duplichecker.com/reverse-image-search.php")
    elif tool == "3":
        webbrowser.open("https://pimeyes.com/en")
    elif tool == "4":
        webbrowser.open("https://smallseotools.com/reverse-image-search/")
    elif tool == "5":
        webbrowser.open("https://imgreverse.com/")
    elif tool == "6":
        webbrowser.open("https://reverseimage.net/")
    elif tool == "7":
        webbrowser.open("https://www.verexif.com/")
    else:
        print("Non valid tool. EXIT ")
        exit()
    


elif category == "9":

    print("SELECT TOOL: ")
    print("1. AperiSolve")
    print("2. Stylesuxx ")
    print("3. StegOnline")

    tool = input("SELECT TOOL NUMBER: ")
    if tool == "1":
        webbrowser.open("www.aperisolve.com/")
    elif tool == "2":
        webbrowser.open("https://stylesuxx.github.io/steganography/")
    elif tool == "3":
        webbrowser.open("https://stegonline.georgeom.net/upload")
    else:
        print("Non valid tool. EXIT ")
        exit()

elif category == "10":

    print("SELECT TOOL: ")
    print("1.  OSINT Dojo framework")
    print("DIAGRAMS // ATTACK SURFACES")
    print("2.  Dark web marketplace attack surface")
    print("3.  Discord attack surface")
    print("4.  Email attack surface")
    print("5.  Gab attack surface")
    print("6.  Gettr attack surface")
    print("7.  Github attack surface")
    print("8.  Image attack surface")
    print("9.  Instagram attack surface")
    print("10. IP attack surface")
    print("11. Mastodon attack surface")
    print("12. Opensea attack surface")
    print("13. Person attack surface")
    print("14. Phone attack surface")
    print("15. Pinterest attack surface")
    print("16. Pokemon Go attack surface")
    print("17. Reddit attack surface")
    print("18. Skype attack surface")
    print("19. Snapchat attack surface")
    print("20. TikTok attack surface")
    print("21. Tumblr attack surface")
    print("22. Twitter attack surface")
    print("23. Usernames attack surface")
    print("24. Website attack surface")
    print("25. Youtube attack surface")

    tool = input("SELECT TOOL NUMBER: ")
    if tool == "1":
        webbrowser.open("https://www.osintdojo.com/resources/")
    elif tool == "2":
        webbrowser.open("https://www.osintdojo.com/diagrams/dwm")
    elif tool == "3":
        webbrowser.open("https://www.osintdojo.com/diagrams/discord")
    elif tool == "4":
        webbrowser.open("https://www.osintdojo.com/diagrams/email")
    elif tool == "5":
        webbrowser.open("https://www.osintdojo.com/diagrams/gab")
    elif tool == "6":
        webbrowser.open("https://www.osintdojo.com/diagrams/gettr")
    elif tool == "7":
        webbrowser.open("https://www.osintdojo.com/diagrams/github")
    elif tool == "8":
        webbrowser.open("https://www.osintdojo.com/diagrams/image")
    elif tool == "9":
        webbrowser.open("https://www.osintdojo.com/diagrams/instagram")
    elif tool == "10":
        webbrowser.open("https://www.osintdojo.com/diagrams/ip")
    elif tool == "11":
        webbrowser.open("https://www.osintdojo.com/diagrams/mastodon")
    elif tool == "12":
        webbrowser.open("https://www.osintdojo.com/diagrams/opensea")
    elif tool == "13":
        webbrowser.open("https://www.osintdojo.com/diagrams/person")
    elif tool == "14":
        webbrowser.open("https://www.osintdojo.com/diagrams/phone")
    elif tool == "15":
        webbrowser.open("https://www.osintdojo.com/diagrams/pinterest")
    elif tool == "16":
        webbrowser.open("https://www.osintdojo.com/diagrams/pokemongo")
    elif tool == "17":
        webbrowser.open("https://www.osintdojo.com/diagrams/reddit")
    elif tool == "18":
        webbrowser.open("https://www.osintdojo.com/diagrams/skype")
    elif tool == "19":
        webbrowser.open("https://www.osintdojo.com/diagrams/snapchat")
    elif tool == "20":
        webbrowser.open("https://www.osintdojo.com/diagrams/tiktok")
    elif tool == "21":
        webbrowser.open("https://www.osintdojo.com/diagrams/tumblr")
    elif tool == "22":
        webbrowser.open("https://www.osintdojo.com/diagrams/twitter")
    elif tool == "23":
        webbrowser.open("https://www.osintdojo.com/diagrams/username")
    elif tool == "24":
        webbrowser.open("https://www.osintdojo.com/diagrams/website")
    elif tool == "25":
        webbrowser.open("https://www.osintdojo.com/diagrams/youtube")
    else:
        print("Non valid tool. EXIT ")
        exit()


elif category == "11":

    print("SELECT TOOL: ")
    print("1.  Bing")
    print("2.  Creative Commons")
    print("3.  DuckDuckGo")
    print("4.  Gibiru")
    print("5.  Onesearch")
    print("6.  Brave")
    print("7.  SearchEncrypt")
    print("8.  Shodan")
    print("9.  Startpage")
    print("10. SwissCows")
    print("11. Wiki")
    print("12. Yahoo")
    print("13. Yandex")
    print("14. 192Search")
    print("15. WaybackMachine")

    tool = input("SELECT TOOL NUMBER: ")
    if tool == "1":
        webbrowser.open("https://www.bing.com/")
    elif tool == "2":
        webbrowser.open("https://search.creativecommons.org/")
    elif tool == "3":
        webbrowser.open("https://duckduckgo.com/")
    elif tool == "4":
        webbrowser.open("https://gibiru.com/")
    elif tool == "5":
        webbrowser.open("https://www.onesearch.com/")
    elif tool == "6":
        webbrowser.open("https://search.brave.com/")
    elif tool == "7":
        webbrowser.open("https://www.searchencrypt.com/home")
    elif tool == "8":
        webbrowser.open("https://www.shodan.io/")
    elif tool == "9":
        webbrowser.open("https://www.startpage.com/es/")
    elif tool == "10":
        webbrowser.open("https://swisscows.com/")
    elif tool == "11":
        webbrowser.open("https://wiki.com/")
    elif tool == "12":
        webbrowser.open("https://www.yahoo.com/")
    elif tool == "13":
        webbrowser.open("https://yandex.com/")
    elif tool == "14":
        webbrowser.open("https://www.192.com/")
    elif tool == "15":
        webbrowser.open("https://archive.org/web/")
    else:
        print("Non valid tool. EXIT ")
        exit()

elif category == "12":

    print("SELECT TOOL: ")
    print("1.  Online Barcode Reader")
    print("2.  Barcode scanner ")
    print("3.  cognex barcode scanner")
    print("4.  Aspose QR reader")
    print("5.  Aspose Barcode scanner")
    print("6.  Lector QR")
    print("7.  Base64 encode/decode")
    print("8.  Caesar cipher")
    print("9.  Pigpen cipher")
    print("10. Solve crypto with force")

    tool = input("SELECT TOOL NUMBER: ")
    if tool == "1":
        webbrowser.open("https://online-barcode-reader.inliteresearch.com/")
    elif tool == "2":
        webbrowser.open("https://nanonets.com/barcode-scanner")
    elif tool == "3":
        webbrowser.open("https://cmbdn.cognex.com/free-barcode-scanner")
    elif tool == "4":
        webbrowser.open("https://products.aspose.app/barcode/es/recognize/qr")
    elif tool == "5":
        webbrowser.open("https://products.aspose.app/barcode/scan#/nocamera")
    elif tool == "6":
        webbrowser.open("https://www.codigos-qr.com/lector-qr-online/")
    elif tool == "7":
        webbrowser.open("https://www.base64decode.org/")
    elif tool == "8":
        webbrowser.open("https://www.dcode.fr/caesar-cipher")
    elif tool == "9":
        webbrowser.open("https://www.boxentriq.com/code-breaking/pigpen-cipher")
    elif tool == "10":
        webbrowser.open("https://scwf.dima.ninja/")
    else:
        print("Non valid tool. EXIT ")
        exit()

elif category == "13":

    print("SELECT TOOL: ")
    print("1. Investing")
    print("2. Coinmarket(historical crypto)")
    print("3. Macrotrends ")
    print("4. WJS Market data")
    print("5. OANDA Historical rates")

    tool = input("SELECT TOOL NUMBER: ")
    if tool == "1":
        webbrowser.open("https://www.investing.com/")
    elif tool == "2":
        webbrowser.open("https://coinmarketcap.com/historical/")
    elif tool == "3":
        webbrowser.open("https://www.macrotrends.net/")
    elif tool == "4":
        webbrowser.open("https://www.wsj.com/market-data/")
    elif tool == "5":
        webbrowser.open("https://www.oanda.com/fx-for-business/historical-rates")
    else:
        print("Non valid tool. EXIT ")
        exit()

elif category == "14":

    print("SELECT TOOL: ")
    print("PLATES")
    print("1.  UK vehicle registration ")
    print("2.  Vehicle history")
    print("3.  Autocheck vehicle history")
    print("4.  Calculadora fecha de matriculacion (ES)")
    print("TRANSPORT")
    print("5.  AirlinesGallery")
    print("6.  Airlines.net")
    print("7.  Airport webcams")
    print("8.  FlightConnections")
    print("9.  SkyScanner")
    print("10. MarineTraffic")
    print("11. Ship tracker")
    print("12. CarNet")
    print("13. VIN check")
    print("14. Rail cab rides ")

    tool = input("SELECT TOOL NUMBER: ")
    if tool == "1":
        webbrowser.open("https://vehicleenquiry.service.gov.uk/")
    elif tool == "2":
        webbrowser.open("https://www.vehiclehistory.com/license-plate-search")
    elif tool == "3":
        webbrowser.open("https://www.autocheck.com/vehiclehistory/search-by-license-plate")
    elif tool == "4":
        webbrowser.open("https://www.seisenlinea.com/calcular-fecha-matriculacion/")
    elif tool == "5":
        webbrowser.open("https://airlinersgallery.smugmug.com/Airline-Tails/Airline-Tails/")
    elif tool == "6":
        webbrowser.open("https://www.airliners.net/")
    elif tool == "7":
        webbrowser.open("https://airportwebcams.net/")
    elif tool == "8":
        webbrowser.open("https://www.flightconnections.com/")
    elif tool == "9":
        webbrowser.open("https://www.skyscanner.net/")
    elif tool == "10":
        webbrowser.open("https://www.marinetraffic.com/")
    elif tool == "11":
        webbrowser.open("https://www.vesselfinder.com/")
    elif tool == "12":
        webbrowser.open("https://carnet.ai/")
    elif tool == "13":
        webbrowser.open("ttps://www.vinaudit.com")
    elif tool == "14":
        webbrowser.open("https://railcabrides.com/en/")
    else:
        print("Non valid tool. EXIT ")
        exit()

elif category == "15":

    print("SELECT TOOL: ")
    print("1. Cyber detective CTF")
    print("2. Cyber investigator CTF")
    print("3. Michael's OSINT CTF")
    print("4. SampleCTF")
    print("5. La Hacktoria CTF's")

    tool = input("SELECT TOOL NUMBER: ")
    if tool == "1":
        webbrowser.open("https://ctf.cybersoc.wales/")
    elif tool == "2":
        webbrowser.open("https://investigator.cybersoc.wales/")
    elif tool == "3":
        webbrowser.open("https://ctf.michweb.de/challenges")
    elif tool == "4":
        webbrowser.open("https://samplectf.com/")
    elif tool == "5":
        webbrowser.open("https://hacktoria.com/")
    else:
        print("Non valid tool. EXIT ")
        exit()
        
else:
        print("Non valid choice. EXIT ")
        exit()



    

   
    
   
    


    