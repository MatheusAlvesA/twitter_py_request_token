# -*- coding: utf-8 -*-
import requests
import time
import urllib.parse
import hashlib
import hmac
import base64

'''

	Developed by: Matheus Alves de Andrade
	Contact: matheusalves.com.br
	2019-10-20

'''

# Fill these informations with the data provided in https://developer.twitter.com/en/apps
consumer_key = '<API KEY>'
consumer_secret = '<API SECRET KEY>'
callback = '<CALLBACK URL>'

conf = {
	'oauth_callback': callback,
	'oauth_consumer_key': consumer_key,
	'oauth_nonce': 'Python Token Generator',
	'oauth_signature_method': 'HMAC-SHA1',
	'oauth_timestamp': str(round(time.time())),
	'oauth_version': '1.0'
}

def HMAC_SHA1(message, key):
    key = bytes(key, 'UTF-8')
    message = bytes(message, 'UTF-8')
    
    digester = hmac.new(key, message, hashlib.sha1)
    signature1 = digester.digest()
    b64_encoded = base64.standard_b64encode(signature1)    
    
    return str(b64_encoded, 'UTF-8')

def percent_encode(source):
	return urllib.parse.quote(source, safe='')

def encode_key_value(key, value):
	return percent_encode(key)+'='+percent_encode(value)

def generate_parameter_string(conf):
	param_list = []
	for key in conf:
		param_list.append(encode_key_value(key, conf[key]))
	param_list.sort()
	return '&'.join(param_list)

def generate_signature_base_string(conf):
	parameter_string = generate_parameter_string(conf)
	return 'POST&'+percent_encode('https://api.twitter.com/oauth/request_token')+'&'+percent_encode(parameter_string)

def generate_signing_key(secret):
	return percent_encode(secret)+'&'

def generate_oauth_signature(config, secret):
	return HMAC_SHA1(generate_signature_base_string(config), generate_signing_key(secret))

def generate_authorization_header(config, secret):
	return 'OAuth oauth_nonce="%s", oauth_callback="%s", oauth_signature_method="HMAC-SHA1", oauth_timestamp="%s", oauth_consumer_key="%s", oauth_signature="%s", oauth_version="1.0"' % (percent_encode(config['oauth_nonce']), percent_encode(config['oauth_callback']), percent_encode(config['oauth_timestamp']), percent_encode(config['oauth_consumer_key']), percent_encode(generate_oauth_signature(config, secret)))

def request_token(config, secret):
	r = requests.post('https://api.twitter.com/oauth/request_token', headers={'Authorization': generate_authorization_header(config, secret)}).text
	raw_list = r.split('&')
	res = {}
	for pair in raw_list:
		temp = pair.split('=')
		res[temp[0]] = temp[1]
	return res


# Generating
tokens = request_token(conf, consumer_secret)
print(tokens, end="\n\n")

print('To test these tokens access:')
print('https://api.twitter.com/oauth/authenticate?oauth_token='+percent_encode(tokens['oauth_token']))
