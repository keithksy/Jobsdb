import random
import requests
import re
import os
import traceback
import datetime
import dateutil
import time
from pathlib import Path
import shutil
import sys
import math

import geventhttpclient
import pycurl
from io import BytesIO

import argparse
import urllib
import logging
import itertools
import errno

import orjson as json
import pandas as pd
import jmespath

from urllib.parse import urlparse
from http.cookies import SimpleCookie
from collections import defaultdict
from collections import Counter

from bs4 import BeautifulSoup
from glob import glob
from gevent.timeout import Timeout as GeventTimeout

log = logging.getLogger("utils")
	    
def request_page(url,referer:str='https://www.google.com',proxy=None,useragent=None,rawcookies=None,force_xml_http_request=False,additional_headers=None,use_raw=False,follow_redirects=True,postdata=None,jsondata=None,maxtries=5,debug=False,sleepsecs=1,search_text='html',abort_text=None,new_session=False,session=None,savefile=None,timeout=30,params={}):
	"""
		Generic wrapper around various get/post requests via a few different libraries including requests, pycurl, and geventhttpclient

		The request is tried multiple tiems based on maxtries.   Once a response is received or the number of tries is exhausted, we take note of the most recent erorr/status code 
		and return if error.  Otherwise the response is post-processed for text that should occur and everything is returned in a dict object

		Args:
			url (str): the url to request
			referer (str): the HTTP referer to use in requesting the url.  defaults to google
			proxy (str): the IP address of the proxy to use
			useragent (str): the user agent to use when making the request
			rawcookies (str): a string containing the cookies that should be in the header when making the request
			force_xml_http_request (bool): If true, then include the X-Requested-With: XmlHttpRequest header
			additional_headers (dict): a dict containing the key and value of additional headers to pass in the request
			use_raw (bool): if True, make the request in the most raw, simple way possible, with limited options and headers, returning raw data
			follow_redirects (bool): if True, follow redirects in the response
			postdata (str): data to be used in the POST request
			jsondata (str): data to be sent via JSON
			maxtries (int): maximum number of tries to make per proxy
			debug (bool): if True, more verbose output for debug purposes
			search_text(str): case-sensitive, if set, search for this text in the response.  If not found, the response would be classified as an error
			abort_text (str): if set and the text is included in the page response, the response would be classified as an error
			new_session (bool): if True, create a new requests.Session for this request
			session (requests.Session): a requests compatible session to use for making the URL request
			savefile (str): if set, save the response to the path set here as savefile 

		Returns:
			dict object containing the html and relevant status codes.  Dict keys include:
				"html" : the raw html from request 
				"has_redirect" : if the request found a response through a redirect, detect and set True

				'user_agent' : user agent used in the request
				'status_code' : HTTP response code
				'session' : requests.Session reference used
				'proxy' : proxy used
				'status_code_prev' : previous status code encountered before the final response was recieved
				'url' : final url requested

				"headers" : response headers, if any
				"error_code" : expanded error code, if any.  includes status_code above, but expanded for further local errors
				"error_msg" : expanded error message, if any
				"has_non_404_error": True if the response had a non-404 error, False otherwise
				"bad_html": if the response did not include the search text, this key holds the original html

		Examples:

			pw.request_page('https://ifconfig.co/json',use_ghttp=True,proxylist=['sfo2proxy:8882'],search_text='time_zone',useragent='Mozzcurl testing-agent ua',force_xml_http_request=True)
	"""


	res = {"error_msg": None, "error_code" : None, "soup": None, "html": None, "ts": None, "url": None, "has_redirect": None}
	page = None 
	tries = 0
	lasterr = None
	lasterr_code = None
	status_code = None
	status_code_prev = None
	res_url = None
	ts = None
	use_proxy = True

	sticky_session = None

	# change log level to debug for the entire WEB module
	if debug:
		log.setLevel(logging.DEBUG)

	_rawcookies = [rawcookies] if rawcookies and type(rawcookies) not in (list,tuple) else rawcookies
	# _tls_fingerprint = [tls_fingerprint] if tls_fingerprint and type(tls_fingerprint) not in (list,tuple) else tls_fingerprint

	while page is None and tries < maxtries:

		status_code = None
		sticky_session = None

		this_useragent = useragent_randomizer() if not useragent else useragent
		if useragent == '__SERVER__':
			log.info(f"using auto/server assigned user agent")
			this_useragent = None
		
		rawcookies = random.choice(_rawcookies) if _rawcookies else None
		# tls_fingerprint = random.choice(_tls_fingerprint) if _tls_fingerprint else None

		try:
			if use_raw:
				page = get_page_raw_requests(url=url,referer=referer,useragent=this_useragent,rawcookies=rawcookies,force_xml_http_request=force_xml_http_request,additional_headers=additional_headers,postdata=postdata,jsondata=jsondata,new_session=new_session,session=session,debug=debug,timeout=timeout)
			else:
				page = get_page_html_requests(url=url,referer=referer,useragent=this_useragent,rawcookies=rawcookies,force_xml_http_request=force_xml_http_request,additional_headers=additional_headers,postdata=postdata,jsondata=jsondata,new_session=new_session,session=session,debug=debug,timeout=timeout)

			status_code = page['status_code']
			status_code_prev = page['status_code_prev']
			sticky_session = page['session']
			res_url = page['url']
			ts = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

			if page and 'html' in page and 'Unable to find image' in str(page['html']):
				status_code = 404
			elif abort_text and page and 'html' in page and abort_text in str(page['html']):
				status_code = 888
				break
			
			if status_code == 200:

				# prelim check for unauthorized access on pages that have a 200, but not the content we are looking for 
				if page and 'html' in page and page['html'] and search_text:
					search_text = [search_text] if type(search_text) not in (list,tuple) else search_text
					has_search_text = [s for s in search_text if s in page['html']] 
					has_search_text = True if len(has_search_text) == len(search_text) else False
					has_access_denied_msg = [s for s in ('UNAUTHORIZED','Unauthorized','unauthorized','Access Denied','ACCESS DENIED','access denied','Forbidden','FORBIDDEN','Access to this page has been denied','Please verify you are a human') if s in page['html']] if not has_search_text else None
					has_not_found_msg = [s for s in ('PAGE COULD NOT BE FOUND','Page Could Not Be Found','page could not be found','URL NOT FOUND','URL Not Found','changed or is temporarily unavailable') if s in page['html']] if not has_search_text else None
					if not has_search_text and has_access_denied_msg:
						# we should retry here, hence we set the page=None and keep the loop, no break
						log.debug(f"HTTP 200 But ACCESS DENIED={has_access_denied_msg} for url: {url}")
						page = None
					elif not has_search_text and has_not_found_msg:
						# we got a 200, but the search text is missing AND we found text that indicates this is really more of a 404
						# so break the loop and abort
						log.debug(f"HTTP 200 but likely 404 instead={has_not_found_msg} for url: {url}")
						status_code = 404
						break

				else:
					continue
			elif status_code == 404:
				log.debug("HTTP error 404 for url: %s" % (url))
				break
			elif status_code == 410:
				log.debug("HTTP error 410 REMOVED for url: %s" % (url))
				break
			elif status_code == 403:
				log.debug("HTTP error 403 FORBIDDEN for url: %s" % (url))
				break
			elif status_code == 429:
				log.warning("HTTP error 429 too many requests for url: %s (tries=%s)" % (url,tries))
				break
			elif status_code == 495:
				log.debug("HTTP error 495 SSL error for url: %s (tries=%s)" % (url,tries))
				break			
			elif status_code == 500:
				log.debug("HTTP error 500 servererror for url: %s (tries=%s)" % (url,tries))
				break	
			elif status_code == 502:
				log.debug("HTTP error 502 bad gateway for url: %s (tries=%s)" % (url,tries))
				break		
			elif status_code == 503:
				log.debug("HTTP error 503 NO SERVICE for url: %s" % (url))
				break
			elif status_code == 504:
				log.debug("HTTP error 504 gateway timeout for url: %s (tries=%s)" % (url,tries))
				break		
			else:
				log.warning("request_page(): Requests Status Error url: %s  status_code=%s" % (url,status_code))
				log.debug(f"last error: {lasterr}")
				time.sleep(sleepsecs * (tries+1))

		except requests.exceptions.ReadTimeout as e:
			log.debug("REQUESTS timeout error when pulling url: %s" % (url))
			lasterr = traceback.format_exc()
			lasterr_code = 408
			sleep_for = 0.5 if use_proxy else (sleepsecs * (tries+1))
			time.sleep(sleep_for)

		except requests.exceptions.TooManyRedirects as e:
			log.debug("REQUESTS timeout error when pulling url: %s" % (url))
			lasterr = traceback.format_exc()
			lasterr_code = 429
			page = None
			break

		except GeventTimeout as e:
			log.debug("REQUESTS gevent-timeout error when pulling url: %s" % (url))
			lasterr = traceback.format_exc()
			lasterr_code = 408
			sleep_for = 0.5 if use_proxy else (sleepsecs * (tries+1))
			time.sleep(sleep_for)

		except requests.exceptions.ChunkedEncodingError as e:
			log.debug("REQUESTS proxy error when pulling url: %s (tries=%s) e=%s" % (url,tries,e))
			lasterr = "requests.ChunkedEncodingError: " + str(e) # traceback.format_exc()
			lasterr_code = 820
			sleep_for = 2 if use_proxy else (sleepsecs * (tries+1)) # usually this is due to the proxy changing ips
			time.sleep(sleep_for)			

		except requests.exceptions.ProxyError as e:
			log.debug("REQUESTS proxy error when pulling url: %s (tries=%s) e=%s" % (url,tries,e))
			lasterr = "requests.ProxyError: " + str(e) # traceback.format_exc()
			lasterr_code = 502
			sleep_for = 2 if use_proxy else (sleepsecs * (tries+1)) # usually this is due to the proxy changing ips
			time.sleep(sleep_for)

		except requests.exceptions.ConnectionError as e:
			log.debug("REQUESTS connection error when pulling url: %s (tries=%s) e=%s" % (url,tries,e))
			lasterr =  "requests.ConnectionError" + str(e) # traceback.format_exc()
			lasterr_code = 720
			sleep_for = 0.5 if use_proxy else (sleepsecs * (tries+1))
			time.sleep(sleep_for)

		except Exception as e:
			if debug: log.warning("ALERT - UNKOWN EXCEPTION WHEN PULLING url: %s (proxy=%s) e=%s" % (url,str(e)))
			lasterr = traceback.format_exc()
			log.warning(lasterr)
			lasterr_code = 730
			time.sleep(sleepsecs * (tries+1))				

		finally:
			tries += 1

			# log all events
			domain = urlparse(url).netloc if url else None
			tbs = traceback.format_list(traceback.extract_stack())
			retailer = None
			arg_list = sys.argv
			if '--a_f' in arg_list:
				retailer = 'proxy_test'
			else:
				retailer_arg = [ arg.split('.py')[0].split('_')[-1] for arg in arg_list if arg and (any( f in arg for f in ('feeds/feed_','/all_legacy_feeds/pull_data_') ) and '.py' in arg) ] if arg_list and isinstance( arg_list, list ) else None
				retailer = retailer_arg[0] if retailer_arg and len(retailer_arg) == 1 else domain
			_lasterr_code = str(lasterr_code) if lasterr_code else None

	res['user_agent'] = useragent
	res['status_code'] = status_code
	res['session'] = sticky_session
	res['status_code_prev'] = status_code_prev
	res['url'] = res_url
	res["has_non_404_error"] = False

	if url and res_url and res_url != url and status_code_prev == 302:
		res['has_redirect'] = True
	else:
		res['has_redirect'] = False
	
	if status_code and status_code >= 400: # in (404,410,403,503):
		msg = "HTTP status %s after %s tries" % (status_code,tries)
		res['error_msg'] = msg
		res['error_code'] = status_code	
		res["has_non_404_error"] = True if status_code != 404 else False
		display_url = re.sub('api_key(=.*)&url','api_key=API_KEY_HIDDEN&url',url)
		log.warning(f"{msg} :: url='{display_url}'")
		return res

	if not page:
		msg = "no page data after %s tries, proxy=%s proxylist=%s lasterr_code=%s lasterr=%s" % (tries,proxy,proxylist,lasterr_code,lasterr)
		res['error_msg'] = msg
		error_code = status_code if status_code else lasterr_code
		res['error_code'] = error_code or 850
		res["has_non_404_error"] = True 

		display_url = re.sub('api_key(=.*)&url','api_key=API_KEY_HIDDEN&url',url)
		log.warning(f"{msg} :: url='{display_url}'")

		return res

	if 'html' not in page:
		log.debug("Unexpected response from request url: " % url)
		res['error_code'] = 800
		res['error_msg'] = "unexpected response (no html key)"
		res["has_non_404_error"] = True 
		return res
	if not page['html']:
		log.debug("No html response from url: %s" % url)
		res['error_code'] = 810
		res['error_msg'] = "html is empty"
		res["has_non_404_error"] = True 
		return res

	if page and 'html' in page:

		# avoid lowercasing the entire page["html"], in the event that it is a massive amount of text
		# search for case-sensitive access denied keywords
		has_access_denied_msg = False
		if search_text:
			has_access_denied_msg = [s for s in ('UNAUTHORIZED','Unauthorized','unauthorized','Access Denied','ACCESS DENIED','access denied','Forbidden','FORBIDDEN','Access to this page has been denied','Please verify you are a human') if s in page['html']]

		if not search_text:
			res['html'] = page['html']
			res['headers'] = page['headers'] if 'headers' in page else None
		elif type(search_text) in (str,bytes,int,float) and search_text in page['html']:
			res['html'] = page['html']
		elif type(search_text) in (list,set):
			found_text = [s for s in search_text if s in page['html']]
			missing_text = [s for s in search_text if s not in found_text]
			if len(found_text) == len(search_text):
				res['html'] = page['html']
			elif has_access_denied_msg:
				res['error_code'] = 403
				res['error_msg'] = f'Missing search text, but found 403 message: {has_access_denied_msg}'
				log.warning(f"Possible 403 Denied, found={has_access_denied_msg}, status_code={status_code} search text {search_text} NOT found in url={url} ... check 'bad_html' key in return data")
				res['bad_html'] = page['html']		
			else:
				res['error_code'] = 999
				res['error_msg'] = 'search text %s NOT found' % missing_text
				res['bad_html'] = page['html']
		elif has_access_denied_msg:
			res['error_code'] = 403
			res['error_msg'] = f'Missing search text, but found 403 message: {has_access_denied_msg}'
			log.warning(f"Possible 403 denied, found={has_access_denied_msg}, status_code={status_code} search text {search_text} NOT found in url={url} ... check 'bad_html' key in return data")
			res['bad_html'] = page['html']			
		else:
			res['error_code'] = 999
			res['error_msg'] = 'search text %s NOT found' % search_text
			log.warning(f"search text {search_text} not found in url={url} ...")
			res['bad_html'] = page['html']
			# log.warning(page['html'])
		res['ts'] = ts
				
	# provide a simple binary true/false if the request was met with some non-404 request error
	res["has_non_404_error"] = True if "error_code" in res and res["error_code"] and (res["error_code"] > 404 or res["error_code"] in (400,401,402,403)) else False

	return res

def get_page_raw_requests(url,referer=None,use_proxy=True,proxy=None,timeout=30,useragent='Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',rawcookies=None,force_xml_http_request=False,additional_headers=None,postdata=None,new_session=False,session=None,verify_ssl=True,savefile=None,debug=False):
	headers = {'user-agent':useragent }
	headers['Accept-Encoding'] = "gzip, deflate, br"
	headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
	headers['Accept-Language'] = 'en-US,en;q=0.9'
	# headers['user-agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36'

	cookies = {}
	if rawcookies:
		cookie = SimpleCookie()
		cookie.load(rawcookies)
		for key, morsel in cookie.items():
			cookies[key] = morsel.value

	if use_proxy and proxy:
		if not proxy.startswith('http'):
			proxies = {"http" : "http://%s" % proxy,"https" : "http://%s" % proxy } 
		else:
			proxies = {"http" : proxy,"https" : proxy }

	elif use_proxy:
		log.warning("no proxy/proxies specified, using local TOR instance as proxy")
		proxies = {"http" : "127.0.0.1:8118","https" : "127.0.0.1:8118"}

	if referer:
		headers['Referer'] = referer 

	if force_xml_http_request:
		headers['X-Requested-With'] =  "XMLHttpRequest"

	if additional_headers:
		headers.update(additional_headers)

	requestor = None
	if new_session:
		session = requests.Session()
		requestor = session
	elif type(session) == requests.Session:
		requestor = session
	else:
		requestor = requests

	# log.info(f"get_page_raw_requests() requesting url={url}, with proxies={proxies}, cookies={cookies}, headers={headers}")
	response = None
	if postdata:
		log.debug(f"REQUESTS POST url={url} proxies={proxies} headers={headers} timeout={timeout} data={postdata} cookies={cookies} verify={verify_ssl}")
		response = requestor.post(url=url,proxies=proxies,headers=headers,timeout=timeout,cookies=cookies,data=postdata,verify=verify_ssl,stream=True)
	else:
		log.debug(f"REQUESTS GET url={url} proxies={proxies} headers={headers} timeout={timeout} cookies={cookies} verify={verify_ssl}")
		response = requestor.get(url=url,proxies=proxies,headers=headers,timeout=timeout,cookies=cookies,verify=verify_ssl,stream=True)


	# we return two status code endpoints for legacy compatibility
	status_code_prev = response.history[0].status_code if response.history else response.status_code
	res =  {"html":response.content,"url":response.url,"status_code": response.status_code,"status": response.status_code, "headers": response.headers, "session": session, "proxy": proxy, "status_code_prev": status_code_prev }
	response.close()
	return res

def get_page_html_requests(url,referer=None,use_proxy=None,proxy=None,timeout=30,useragent='Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',rawcookies=None,force_xml_http_request=False,additional_headers=None,jsondata=None,postdata=None,new_session=False,session=None,verify_ssl=True,savefile=None,debug=False,get_flaresolvr_cookie=False):
	# useragent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:77.0) Gecko/20100101 Firefox/77.0'
	# accept_header = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
	accept_header = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
	# accept_header = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
	accept_enc = 'gzip, deflate, compress, br, identity' # 'Accept-Encoding'
	accept_lang = 'en-US,en;q=0.5'
	headers = {'user-agent':useragent, 'accept': accept_header, 'accept-encoding': accept_enc, 'accept-language': accept_lang, 'dnt': '1', 'upgrade-insecure-requests': '1'}
	
	# if proxy and '@' in proxy and proxy.count(':') == 2:

	#	auth, paddr = proxy.split('@')
	#	puser,ppass = auth.split(':')

	cookies = {}
	if rawcookies:
		cookie = SimpleCookie()
		cookie.load(rawcookies)
		for key, morsel in cookie.items():
			cookies[key] = morsel.value

	# if use_proxy and proxy:
	# 	if not proxy.startswith('http'):
	# 		proxies = {"http" : "http://%s" % proxy,"https" : "http://%s" % proxy } 
	# 	else:
	# 		proxies = {"http" : proxy,"https" : proxy } 
	
	# elif use_proxy:
	# 	log.warning("no proxy/proxies specified, using local TOR instance as proxy")
	# 	proxies = {"http" : "127.0.0.1:8118","https" : "127.0.0.1:8118"}

	if referer:
		headers['referer'] = referer 

	if force_xml_http_request:
		headers['X-Requested-With'] =  "XMLHttpRequest"

	if additional_headers:
		headers.update(additional_headers)

	requestor = None
	if new_session:
		session = requests.Session()
		requestor = session
	elif type(session) == requests.Session:
		requestor = session
	else:
		requestor = requests

	response = None
	if postdata:
		log.debug(f"REQUESTS POST url={url} headers={headers} timeout={timeout} data={postdata} cookies={cookies}")
		response = requestor.post(url=url,headers=headers,timeout=timeout,data=postdata,cookies=cookies,verify=verify_ssl)
	else:
		log.debug(f"REQUESTS GET headers={headers} timeout={timeout} url={url} cookies={cookies}")
		response = requestor.get(url=url,headers=headers,timeout=timeout,cookies=cookies,verify=verify_ssl)
	
	# log.debug(response.text)
	log.debug(response.request.headers)

	# we return two status code endpoints for legacy compatibility
	status_code_prev = response.history[0].status_code if response.history else response.status_code
	res = {"html":response.text,"url":response.url,"status_code": response.status_code,"status": response.status_code, "session": session, "proxy": proxy, "status_code_prev": status_code_prev }
	response.close()
	return res


def useragent_randomizer(agent_type='desktop'):
	"""
		Get a random user agent from a list of acceptable agents often seen in product

		Args:
			agent_type (str): if 'mobile', return a random mobile agent, otherwise return a random desktop user agent

		Returns:
			A random user agent string
	"""
	desktop_agents = [
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.2 Safari/605.1.15',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36',
		'Mozilla/5.0 (X11; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36',
		'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36',
		'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Safari/605.1.15',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Safari/605.1.15',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.67 Safari/537.36',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Safari/605.1.15',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36'
	]
	mobile_agents = [
		'Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1',
		'Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/69.0.3497.105 Mobile/15E148 Safari/605.1',
		'Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/13.2b11866 Mobile/16A366 Safari/605.1.15',
		'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1',
		'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.34 (KHTML, like Gecko) Version/11.0 Mobile/15A5341f Safari/604.1',
		'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A5370a Safari/604.1',
		'Mozilla/5.0 (iPhone9,3; U; CPU iPhone OS 10_0_1 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A403 Safari/602.1',
		'Mozilla/5.0 (Linux; Android 8.0.0; SM-G960F Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.84 Mobile Safari/537.36',
		'Mozilla/5.0 (Linux; Android 7.0; SM-G892A Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Mobile Safari/537.36',
		'Mozilla/5.0 (Linux; Android 7.0; SM-G930VC Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/58.0.3029.83 Mobile Safari/537.36',
		'Mozilla/5.0 (Linux; Android 6.0.1; SM-G935S Build/MMB29K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/55.0.2883.91 Mobile Safari/537.36',
		'Mozilla/5.0 (Linux; Android 6.0.1; SM-G920V Build/MMB29K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.98 Mobile Safari/537.36',
		'Mozilla/5.0 (Linux; Android 5.1.1; SM-G928X Build/LMY47X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.83 Mobile Safari/537.36',
		'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 6P Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.83 Mobile Safari/537.36',
		'Mozilla/5.0 (Linux; Android 7.1.1; G8231 Build/41.2.A.0.219; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36',
		'Mozilla/5.0 (Linux; Android 6.0.1; E6653 Build/32.2.A.0.253) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.98 Mobile Safari/537.36',
		'Mozilla/5.0 (Linux; Android 6.0; HTC One X10 Build/MRA58K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/61.0.3163.98 Mobile Safari/537.36'
	]
 
	useragent = random.choice(mobile_agents) if agent_type == 'mobile' else random.choice(desktop_agents)
	return useragent