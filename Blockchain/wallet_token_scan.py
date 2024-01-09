'''
Data Collection & Analysis:

- Retrieves and analyzes Ethereum address data from Merkle Science.
- Identifies risks using trigger words for originators and beneficiaries.
- Fetches token information and calculates market data changes.

Smart Contract Scan:
- Submits contracts for vulnerability scans and retrieves results.

Email Notification:
- Sends an email with analysis results as an attachment.

REMOVED PARTS:
- "Token Score" calculation based on volatility
- Full API implementation, only functions left

'''



from fastapi import FastAPI
import requests
import json
from pycoingecko import CoinGeckoAPI
import time
import string
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders




letters = string.ascii_uppercase
random_string = (''.join(random.choice(letters) for i in range(16)))
file_name = "result_" + random_string + ".txt"
file_object = open(file_name, 'a')

app = FastAPI()
cg = CoinGeckoAPI()

headers = {
    'accept: */*'
}

#   Merkle Science Data Collection & Analysis section

# 1 - ETH
# 0 - BTC
merkle_currency_id = '1'

trigger_words = ["Darknet", "Coin Mixer", "Scam", "Extortion", "Malware", "Theft", "Sanctions",
                 "High Risk Organization", "Law Enforcement"]

# For testing - remove for prod
address = "0x626DE9Ccf39BA6058F2aaDb8D3e59EFAaDb1AFBb"
network = "ropsten"

def merkle_scan(address):
    url = "http://xx.xx.xx.xx:3000/msv3/addresses/"
    headers = {
        'Content-Type': 'application/json'
    }
    payload = json.dumps({
        "identifier": address,
        "currency": merkle_currency_id
    })

    response = requests.request("POST", url, headers=headers, data=payload)
    return json.loads(response.text)


def merkle_analysis():
    merkle_data = merkle_scan(address)
    merkle_risk = merkle_data['risk_level_verbose']

    # Originator Analysis
    originator_risk = []

    if len(merkle_data['originator']) == {}:
        originator_risk[0] = "No risks associated with originators found"
    else:
        i = 0
        while i < len(merkle_data['originator']):
            originator_risk.append(merkle_data['originator'][i]["tag_type_verbose"])
            i += 1

    # Beneficiary Extraction
    beneficiary_risk = []

    if len(merkle_data['beneficiary']) == {}:
        beneficiary_risk[0] = "No risks associated with beneficiaries found"
    else:
        i = 0
        while i < len(merkle_data['beneficiary']):
            beneficiary_risk.append(merkle_data['beneficiary'][i]["tag_type_verbose"])
            i += 1

    # Find matches between trigger words and lists of originators & beneficiaries

    final_list_of_originators = set(originator_risk) & set(trigger_words)
    final_list_of_beneficiaries = set(beneficiary_risk) & set(trigger_words)

    if len(final_list_of_beneficiaries) == 0:
        final_list_of_beneficiaries = "No risky beneficiaries found"

    if len(final_list_of_originators) == 0:
        final_list_of_originators = "No risky beneficiaries found"

    print("Address: " + address)
    file_object.write("Address: " + address + '\n')

    print("Merkle Risk: " + str(merkle_risk))
    file_object.write("Merkle Risk: " + str(merkle_risk) + '\n')

    print("List of Originators: " + str(final_list_of_originators))
    file_object.write("List of Originators: " + str(final_list_of_originators) + '\n')

    print("List of Beneficiaries: " + str(final_list_of_beneficiaries))
    file_object.write("List of Beneficiaries: " + str(final_list_of_beneficiaries) + '\n')

    return address, str(merkle_risk), str(final_list_of_originators), str(final_list_of_beneficiaries)


merkle_result = merkle_analysis()


def get_wallet_tokens(address, network):
    url = "http://xx.xx.xx.xx:3000/scan/contracts"

    payload = json.dumps({
        "network": network,
        "address": address
    })
    headers = {
        'Content-Type': 'application/json'
    }

    wallet_tokens = requests.request("POST", url, headers=headers, data=payload)
    return json.loads(wallet_tokens.text)


wallet_tokens_data = get_wallet_tokens(address, network)

wallet_tokensName_list = []
wallet_tokenContract_list = []
price_change = []
volume_change = []

i = 0
while i < len(wallet_tokens_data):
    wallet_tokensName_list.append(wallet_tokens_data[i]['tokenName'])
    wallet_tokenContract_list.append(wallet_tokens_data[i]['contract'])
    i += 1


i = 0
while i < len(wallet_tokensName_list):
    try:
        # Get Price data
        coin_market_data = cg.get_coin_by_id(id=str(wallet_tokensName_list[i]).lower(), localization=False,
                                             community_data=False, developer_data=False, sparkline=False)
        price_change_1D = coin_market_data['market_data']['price_change_percentage_24h']
        price_change_7D = coin_market_data['market_data']['price_change_percentage_7d']
        price_change_30D = coin_market_data['market_data']['price_change_percentage_30d']
        price_change.append([price_change_1D, price_change_7D, price_change_30D])

        # Volume calculation
        # q_volume = cg.get_coin_market_chart_by_id(id="uniswap", vs_currency="usd", days='max', interval='daily')
        q_volume = cg.get_coin_market_chart_by_id(id=str(wallet_tokensName_list[i]).lower(), vs_currency="usd",
                                                  days='max', interval='daily')

        volume_1D = q_volume['total_volumes'][-1][1]
        volume_2D = q_volume['total_volumes'][-2][1]

        volume_change_24h_percentage = float(((volume_1D - volume_2D) * 100) / volume_2D)

        # Calculate total volume for last 7D
        volume_1W = 0
        day = 1
        while day <= 7:
            volume_1W += q_volume['total_volumes'][-day][1]
            day += 1

        # Calculate total volume between last 14 & 7 days
        volume_2W = 0
        day = 7  # start summing up values from second-last entry
        while day <= 14:
            volume_2W += q_volume['total_volumes'][-day][1]
            day += 1

        volume_change_7d_percentage = float(((volume_1W - volume_2W) * 100) / volume_2W)

        # Calculate total volume for last 30D aka 1M
        volume_1M = 0
        day = 1
        while day <= 30:
            volume_1M += q_volume['total_volumes'][-day][1]
            day += 1

        # Calculate total volume between 30 and 60 days
        volume_2M = 0
        day = 31  # start summing up values from second-last entry
        while day <= 60:
            volume_2M += q_volume['total_volumes'][-day][1]
            day += 1

        volume_change_30d_percentage = float(((volume_1M - volume_2M) * 100) / volume_2M)

        volume_change.append(
            [volume_change_24h_percentage, volume_change_7d_percentage, volume_change_30d_percentage])


    except:
        price_change.append("No reliable market data found")
        volume_change.append("No reliable market data found")

    i += 1


url = "http://xx.xx.xx.xx:3000/mythril/submitSmartContract"
uuid_list = []

# submit contracts for scan
for i in range(0, len(wallet_tokenContract_list)):

    payload = json.dumps({
        "network": network,
        "contract": wallet_tokenContract_list[i]
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    uuid_list.append(json.loads(response.text)['uuid'])


print("----------")
file_object.write("----------" + '\n')

print("Found " + str(len(wallet_tokensName_list)) + " tokens total.")
file_object.write("Found " + str(len(wallet_tokensName_list)) + " tokens total." + '\n')

print("Market Data:")
for i in range(0, len(wallet_tokensName_list)):
    print(wallet_tokensName_list[i])
    file_object.write(wallet_tokensName_list[i] + '\n')
    if (price_change[i] == "No reliable market data found"):
        print("Price: No reliable market data found")
        file_object.write("Price: No reliable market data found" + '\n')
    else:
        print("Price change:")
        print("24h: " + str(price_change[i][0]))
        print("1W: " + str(price_change[i][1]))
        print("1M: " + str(price_change[i][2]))
        file_object.write("Price change:" + '\n')
        file_object.write("24h: " + str(price_change[i][0]) + '\n')
        file_object.write("1W: " + str(price_change[i][1]) + '\n')
        file_object.write("1M: " + str(price_change[i][2]) + '\n')

    if (volume_change[i] == "No reliable market data found"):
        print("Volume: No reliable market data found")
        file_object.write("Volume: No reliable market data found" + '\n')
    else:
        print("Volume change:")
        print("24h: " + str(volume_change[i][0]))
        print("1W: " + str(volume_change[i][1]))
        print("1M: " + str(volume_change[i][2]))
        file_object.write("Volume change:" + '\n')
        file_object.write("24h: " + str(volume_change[i][0]) + '\n')
        file_object.write("1W: " + str(volume_change[i][1]) + '\n')
        file_object.write("1M: " + str(volume_change[i][2]) + '\n')
    print("----------")
    file_object.write("----------" + '\n')

# uuid_list provided manually for testing - remove in prod
uuid_list1 = ['39848-33853-80238', '65984-22441-21047', '28642-6289-61506']
scan_results = []

print("Smart Contract Vulnerability scan: ")
file_object.write("Smart Contract Vulnerability scan: ")
time.sleep(3600)

for i in range(0, len(wallet_tokenContract_list)):

    url = "http://xx.xx.xx.xx:3000/mythril/queryStatus/" + str(uuid_list1[i])

    payload = ""
    headers = {}

    response = requests.request("GET", url, headers=headers, data=payload)
    print("Scan status for " + str(wallet_tokensName_list[i]) + ": " + str(json.loads(response.text)['status']))
    print("Contract: " + str(wallet_tokenContract_list[i]))
    print(json.loads(response.text)['numVulnerabilities'])
    print("----------")
    file_object.write("Scan status for " + str(wallet_tokensName_list[i]) + ": " + str(json.loads(response.text)['status']) + '\n')
    file_object.write("Contract: " + str(wallet_tokenContract_list[i]) + '\n')
    file_object.write(str(json.loads(response.text)['numVulnerabilities']) + '\n')
    file_object.write("----------" + '\n')
file_object.close()



fromaddr = "xxx@xxx.com"
toaddr = "xxx@xxx.com"

msg = MIMEMultipart()

msg['From'] = fromaddr
msg['To'] = toaddr
msg['Subject'] = "XXX Scan Results"

body = "Your XXX scan result is ready. Please see file attached for the results."

msg.attach(MIMEText(body, 'plain'))

filename = file_name
attachment = open(file_name, "rb")

part = MIMEBase('application', 'octet-stream')
part.set_payload((attachment).read())
encoders.encode_base64(part)
part.add_header('Content-Disposition', "attachment; filename= %s" % filename)

msg.attach(part)

server = smtplib.SMTP('smtp.xxx.com', 111)
server.starttls()
server.login(fromaddr, "xxxx")
text = msg.as_string()
server.sendmail(fromaddr, toaddr, text)
server.quit()