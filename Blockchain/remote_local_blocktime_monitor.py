'''
Within our internal infrastructure, blockchain technology serves as the backbone. Ensuring synchronization 
between the block times stored in our internal servers and the actual block times on the blockchains was critical.

This script initially served as a temporary solution for alerting discrepancies in block times. 
However, in the inevitable way of such things, what was intended as a "temporary" solution became permanent in the startup.
'''

import mysql.connector
from web3 import Web3
from web3.middleware import geth_poa_middleware
from datetime import *
import requests
import json

# Monitors for Blocktime difference between local DB and remote node. Currently supported:
#       AVAX  BTC  Polygon  Fuji (AVAX Testnet)
#       BCH   ETH  BTCTest  PolygonTest 
#       BSC   LTC  ETCTest


mydb = mysql.connector.connect(
    host="xx.16.9.xx",
    port=3306,
    user="xxx",
    password="xxx",
    database="light_wallet")


def get_chain_blocktime_localDB(chain):  # Values: ETH, AVAX, FUJI, MATIC
    mycursor = mydb.cursor()

    chain_name = chain
    mycursor.execute("SELECT block_time FROM light_wallet_mainchain WHERE chain_name='" +
                     chain_name+"' ORDER BY height DESC LIMIT 1;")
    myresult = mycursor.fetchall()
    time_format = myresult[0][0]
    return (time_format)


def send_slack_message(payload, webhook):
    """Send a Slack message to a channel via a webhook. 

    Args:
        payload (dict): Dictionary containing Slack message, i.e. {"text": "This is a test"}
        webhook (str): Full Slack webhook URL for your chosen channel. 

    Returns:
        HTTP response code, i.e. <Response [503]>
    """

    return requests.post(webhook, json.dumps(payload))



################################################
# Functions to get blocktime from remote nodes #
################################################


def get_ETC_blocktime():

    url = "https://www.oklink.com/api/v5/explorer/blockchain/info?chainShortName=etc"

    headers = {
        'Ok-Access-Key': ENV
        }

    response = requests.request("GET", url, headers=headers)
    json_data = json.loads(response.text)
    ETC_block_time = json_data['data'][0]['lastBlockTime']
    ETC_block_datetime = datetime.fromtimestamp(int(ETC_block_time[:-3]))
    return ETC_block_datetime

def get_BCH_blocktime():
    
    url = "https://svc.blockdaemon.com/universal/v1/bitcoincash/mainnet/sync/block_number?apiKey=ENV"

    response = requests.request("GET", url)
    url = "https://svc.blockdaemon.com/universal/v1/bitcoincash/mainnet/block/780578?apiKey=ENV"

    response = requests.request("GET", url)
    json_data = json.loads(response.text)
    bch_block_latest = json_data['date']
    bch_block_datetime = datetime.fromtimestamp(
        int(bch_block_latest))
    return bch_block_datetime

def get_LTC_blocktime():
    
    url = "https://chainz.cryptoid.info/ltc/api.dws?q=getblockcount"


    response = requests.request("GET", url)
    ltc_block_height = response.text

    url = "https://chainz.cryptoid.info/ltc/api.dws?q=getblocktime&height="+ltc_block_height
    response = requests.request("GET", url)
    ltc_block_time = response.text
    return datetime.fromtimestamp(int(ltc_block_time))

def get_BTC_test_blocktime():
    url = "https://dry-fluent-brook.btc-testnet.discover.quiknode.pro/ENV"

    payload = json.dumps({
        "method": "getblockcount"
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    json_data = json.loads(response.text)
    btc_block_latest = json_data['result']
    payload = json.dumps({
        "method": "getblockhash",
        "params": [
            btc_block_latest
        ]
    })
    response = requests.request("POST", url, headers=headers, data=payload)
    json_data = json.loads(response.text)
    btc_block_hash = json_data['result']
    payload = json.dumps({
        "method": "getblock",
        "params": [
            btc_block_hash
        ]
    })
    response = requests.request("POST", url, headers=headers, data=payload)
    json_data = json.loads(response.text)
    btc_block_time = json_data['result']['time']
    btc_block_datetime = datetime.fromtimestamp(int(btc_block_time))
    return btc_block_datetime

def get_BTC_blocktime():
    url = "https://alien-frequent-sponge.btc.discover.quiknode.pro/ENV"


    payload = json.dumps({
        "method": "getblockcount"
        })
    headers = {
    'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    json_data = json.loads(response.text)
    btc_block_latest = json_data['result']
    payload = json.dumps({
        "method": "getblockhash",
        "params": [
            btc_block_latest
        ]
    })
    response = requests.request("POST", url, headers=headers, data=payload)
    json_data = json.loads(response.text)
    btc_block_hash = json_data['result']
    payload = json.dumps({
        "method": "getblock",
        "params": [
            btc_block_hash
        ]
    })
    response = requests.request("POST", url, headers=headers, data=payload)
    json_data = json.loads(response.text)
    btc_block_time = json_data['result']['time']
    btc_block_datetime = datetime.fromtimestamp(int(btc_block_time))
    return btc_block_datetime

def get_MATIC_test_blocktime():

    ct = datetime.now()
    ts = ct.timestamp()
    url = "https://api-testnet.polygonscan.com/api?module=block&action=getblocknobytime&timestamp=" + \
        str(int(ts)) + "&closest=before&apikey=ENV"
    r = requests.get(url)
    data = r.json()

    block_time = (data['result'])

    url = "https://api-testnet.polygonscan.com/api?module=block&action=getblockreward&blockno=" + \
        str(block_time) + "&apikey=ENV"
    r = requests.get(url)
    data = r.json()
    MATIC_test_timestamp = data['result']['timeStamp']
    MATIC_test_block_datetime = datetime.fromtimestamp(
        int(MATIC_test_timestamp))
    return MATIC_test_block_datetime

def get_MATIC_blocktime():

    ct = datetime.now()
    ts = ct.timestamp()
    url = "https://api.polygonscan.com/api?module=block&action=getblocknobytime&timestamp=" + \
        str(int(ts)) + "&closest=before&apikey=ENV"
    r = requests.get(url)
    data = r.json()

    block_time = (data['result'])

    url = "https://api.polygonscan.com/api?module=block&action=getblockreward&blockno=" + \
        str(block_time) + "&apikey=ENV"
    r = requests.get(url)
    data = r.json()
    MATIC_timestamp = data['result']['timeStamp']
    MATIC_block_datetime = datetime.fromtimestamp(int(MATIC_timestamp))
    return MATIC_block_datetime

def get_FUJI_blocktime():

    ct = datetime.now()
    ts = ct.timestamp()
    url = "https://api-testnet.snowtrace.io/api?module=block&action=getblocknobytime&timestamp=" + \
        str(int(ts)) + "&closest=before&apikey=ENV"
    r = requests.get(url)
    data = r.json()

    block_time = (data['result'])

    url = "https://api-testnet.snowtrace.io/api?module=block&action=getblockreward&blockno=" + \
        str(block_time) + "&apikey=ENV"
    r = requests.get(url)
    data = r.json()
    FUJI_timestamp = data['result']['timeStamp']
    FUJI_block_datetime = datetime.fromtimestamp(int(FUJI_timestamp))
    return FUJI_block_datetime

def get_BSC_blocktime():

    ct = datetime.now()
    ts = ct.timestamp()
    url = "https://api.bscscan.com/api?module=block&action=getblocknobytime&timestamp=" + \
        str(int(ts)) + "&closest=before&apikey=ENV"
    r = requests.get(url)
    data = r.json()

    block_time = (data['result'])

    url = "https://api.bscscan.com/api?module=block&action=getblockreward&blockno=" + \
        str(block_time) + "&apikey=ENV"
    r = requests.get(url)
    data = r.json()
    BSC_timestamp = data['result']['timeStamp']
    BSC_block_datetime = datetime.fromtimestamp(int(BSC_timestamp))
    return BSC_block_datetime

def get_AVAX_blocktime():
    ct = datetime.now()
    ts = ct.timestamp()
    url = "https://api.snowtrace.io/api?module=block&action=getblocknobytime&timestamp=" + \
        str(int(ts)) + "&closest=before&apikey=ENV"
    r = requests.get(url)
    data = r.json()

    block_time = (data['result'])

    url = "https://api.snowtrace.io/api?module=block&action=getblockreward&blockno=" + \
        str(block_time) + "&apikey=ENV"
    r = requests.get(url)
    data = r.json()
    AVAX_timestamp = data['result']['timeStamp']
    AVAX_block_datetime = datetime.fromtimestamp(int(AVAX_timestamp))
    return AVAX_block_datetime

def get_ETH_blocktime():
    w3 = Web3(Web3.HTTPProvider(
        'https://mainnet.infura.io/v3/ENV'))

    eth_block_time = w3.eth.get_block('latest')
    eth_block_datetime = datetime.fromtimestamp(eth_block_time.timestamp)

    return (eth_block_datetime)

def time_diff(remote, local):
    if remote > local:
        return remote - local
    else:
        return local - remote



# TODO: implement a function to compare timestamps
# Local DB
local_ETH = get_chain_blocktime_localDB("ETH")
local_FUJI = get_chain_blocktime_localDB("FUJI")
local_MATIC = get_chain_blocktime_localDB("Polygon")
local_MATIC_test = get_chain_blocktime_localDB("PolygonTest")
local_AVAX = get_chain_blocktime_localDB("AVAX")
local_BTC = get_chain_blocktime_localDB("BTC")
local_BTC_test = get_chain_blocktime_localDB("BTCTest")
local_LTC = get_chain_blocktime_localDB("LTC")
local_BCH = get_chain_blocktime_localDB("BCH")
local_ETC = get_chain_blocktime_localDB("ETC")
local_BSC = get_chain_blocktime_localDB("BSC")


# Remote API
remote_ETH = get_ETH_blocktime()
remote_FUJI = get_FUJI_blocktime()
remote_MATIC = get_MATIC_blocktime()
remote_MATIC_test = get_MATIC_test_blocktime()
remote_AVAX = get_AVAX_blocktime()
remote_BTC = get_BTC_blocktime()
remote_BTC_test = get_BTC_test_blocktime()
remote_LTC = get_LTC_blocktime()
remote_BCH = get_BCH_blocktime()
remote_ETC = get_ETC_blocktime()
remote_BSC = get_BSC_blocktime()


# Slack Webhook notification


webhook = "https://hooks.slack.com/services/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"
payload = {
	"blocks": [
		{
			"type": "header",
			"text": {
				"type": "plain_text",
				"text": "Me3 Block time monitoring"
			}
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*ETH local:* \n*ETH remote:* \n*Difference:*"
			}
		},
		{
			"type": "divider"
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*FUJI local:* \n*FUJI remote:* \n*Difference:*"
			}
		},
		{
			"type": "divider"
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*MATIC local:* \n*MATIC remote:* \n*Difference:*"
			}
		},
		{
			"type": "divider"
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*MATIC_test local:* \n*MATIC_test remote:* \n*Difference:*"
			}
		},
		{
			"type": "divider"
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*AVAX local:* \n*AVAX remote:* \n*Difference:*"
			}
		},
		{
			"type": "divider"
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*BTC local:* \n*BTC remote:* \n*Difference:*"
			}
		},
		{
			"type": "divider"
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*BTC_test local:* \n*BTC_test remote:* \n*Difference:*"
			}
		},
		{
			"type": "divider"
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*LTC local:* \n*LTC remote:* \n*Difference:*"
			}
		},
		{
			"type": "divider"
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*BCH local:* \n*BCH remote:* \n*Difference:*"
			}
		},
		{
			"type": "divider"
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*ETC local:* \n*ETC remote:* \n*Difference:*"
			}
		},
		{
			"type": "divider"
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*BSC local:* \n*BSC remote:* \n*Difference:*"
			}
		},
		{
			"type": "divider"
		}
	]
}
send_slack_message(payload, webhook)
mydb.close()

# Debug 
'''
print('remote_ETH', remote_ETH)
print('remote_FUJI', remote_FUJI)
print('remote_MATIC', remote_MATIC)
print('remote_AVAX', remote_AVAX)
print('remote_BSC', remote_BSC)
print('remote_MATIC_test', remote_MATIC_test)
print('remote_BTC_test', remote_BTC_test)
print('remote_BTC', remote_BTC)
print('remote_LTC', remote_LTC)
print('remote_BCH', remote_BCH)
print('remote_ETC', get_ETC_blocktime())
'''