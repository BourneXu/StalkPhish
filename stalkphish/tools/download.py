#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish

import requests
import os
import re
import getopt
import sys
import json
import hashlib
import socket
import zipfile
import warnings
import sqlite3
import redis
from bs4 import BeautifulSoup
#from os.path import dirname
from lxml import html, etree
from urllib.parse import urlparse
from tools.utils import TimestampNow
from tools.utils import VerifyPath
from tools.utils import SHA256
from tools.utils import UAgent
from tools.sqlite import SqliteCmd
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Connexion tests, Phishing kits downloadingd
def TryPKDownload(siteURL,siteDomain,IPaddress,TABLEname,InvTABLEname,DLDir,SQL,PROXY,LOG,UAFILE):
	global ziplist
	proxies = {'http': PROXY, 'https': PROXY}
	UAG = UAgent()
	UA = UAG.ChooseUA(UAFILE)
	user_agent = {'User-agent': UA}
	now = str(TimestampNow().Timestamp())
	SHA = SHA256()

	PsiteURL = None
	ResiteURL = siteURL
	PsiteURL = urlparse(ResiteURL)
	if len(PsiteURL.path.split("/")[1:]) >= 2:
		siteURL = ResiteURL.rsplit('/', 1)[0]
	else:
		siteURL = ResiteURL

	# Let's try to find a phishing kit source archive
	try:
		r = requests.get(siteURL, headers=user_agent, proxies=proxies, allow_redirects=True, timeout=(5,12), verify=False)
		

		if (str(r.status_code) != "404"):
			LOG.info("["+str(r.status_code)+"] "+r.url)
			SQL.SQLiteInsertStillTryDownload(TABLEname, siteURL)
			if SQL.SQLiteInvestigVerifyEntry(InvTABLEname, siteDomain, IPaddress) is 0:
				SQL.SQLiteInvestigInsert(InvTABLEname, siteURL, siteDomain, IPaddress, now, str(r.status_code))
			else:
				pass
			ziplist = []
			path = siteURL
			pathl = '/' .join(path.split("/")[:3])
			pathlist = path.split("/")[3:]

			# Make list
			current=0
			newpath=""
			while current < len(pathlist):
				if current == 0:
					newpath = pathlist[current]
				else:
					newpath = newpath+"/"+pathlist[current]
				current = current + 1
				pathD = pathl+"/"+newpath
				ziplist.append(pathD)

			# Get page title
			try:
				if len(ziplist) >= 1:
					rhtml=requests.get(siteURL, headers=user_agent, proxies=proxies, allow_redirects=True, timeout=(5,12), verify=False)
					thtml = rhtml.text
					tit = re.search('<title>(.*?)</title>', thtml, re.IGNORECASE)
					if tit is not None:
						PageTitle=tit.group(1)
						LOG.info(PageTitle)
						SQL.SQLiteInvestigUpdateTitle(InvTABLEname, siteURL, PageTitle)
					else:
						pass
			except AttributeError:
				pass
			except requests.exceptions.ReadTimeout:
				pass
			except:
				err = sys.exc_info()
				LOG.error("Get PageTitle Error: " +siteURL+ str(err))

			# Set redis to record URL Done list
			redis_set = redis.Redis(db=1)
			redis_set.sadd('StalkPhishURLs', 0)

			# Try to retrieve all possible path for one url and find whether there are .zip files
			try:
				if len(ziplist) >= 1:
					for url in ziplist:
						if redis_set.sismember('StalkPhishURLs', url):
							continue
						LOG.info("Retrieving Path "+ url)
						urllist = RetriveIndexPath(url, proxies, user_agent, [])
						redis_set.sadd('StalkPhishURLs', *urllist, url)
						for urlzip in urllist:
							LOG.info("trying "+ urlzip)
							rz = requests.get(urlzip, headers=user_agent, proxies=proxies, allow_redirects=True, timeout=(5,12), verify=False)
							if str(rz.status_code) != "404":
								lastHTTPcode = str(rz.status_code)
								zzip = urlzip.replace('/', '_').replace(':', '')
								try:
									if "application/zip" in rz.headers['content-type'] or "application/octet-stream" in rz.headers['content-type']:
										savefile=DLDir+zzip
										# Still collected file
										if os.path.exists(savefile):
											LOG.info("[DL ] Found still collected archive: "+savefile)
											return
										# New file to download
										else:
											LOG.info("[DL ] Found archive, downloaded it as: "+savefile)
											with open(savefile, "wb") as code:
												code.write(rz.content)
												pass
											ZipFileName = str(zzip)
											ZipFileHash = SHA.hashFile(savefile)
											SQL.SQLiteInvestigUpdatePK(InvTABLEname,siteURL,ZipFileName,ZipFileHash,now,lastHTTPcode)
											return
									else:
										pass
								except requests.exceptions.ContentDecodingError:
									LOG.error("[DL ] content-type error")
								except:
									pass
								# 404
							else:
								pass
			except:
				err = sys.exc_info()
				LOG.error("DL Error: " + str(err))

			try:
				# Try too find and download phishing kit archive (.zip)
				if len(ziplist) >= 1:
					for zip in ziplist:
						if redis_set.sismember('StalkPhishURLs', zip+".zip"):
							continue
						else:
							redis_set.sadd('StalkPhishURLs', zip+".zip")
						if ('=' or '%' or '?' or '-' or '@') not in os.path.basename(os.path.normpath(zip)):
							try:
								LOG.info("trying "+zip+".zip")
								rz = requests.get(zip+".zip", headers=user_agent, proxies=proxies, allow_redirects=True, timeout=(5,12), verify=False)
								if str(rz.status_code) != "404":
									lastHTTPcode = str(rz.status_code)
									zzip = zip.replace('/', '_').replace(':', '')
									try:
										if "application/zip" in rz.headers['content-type'] or "application/octet-stream" in rz.headers['content-type']:
											savefile=DLDir+zzip+'.zip'
											# Still collected file
											if os.path.exists(savefile):
												LOG.info("[DL ] Found still collected archive: "+savefile)
												return
											# New file to download
											else:
												LOG.info("[DL ] Found archive, downloaded it as: "+savefile)
												with open(savefile, "wb") as code:
													code.write(rz.content)
													pass
												ZipFileName = str(zzip+'.zip')
												ZipFileHash = SHA.hashFile(savefile)
												SQL.SQLiteInvestigUpdatePK(InvTABLEname,siteURL,ZipFileName,ZipFileHash,now,lastHTTPcode)
												return
										else:
											pass
									except requests.exceptions.ContentDecodingError:
										LOG.error("[DL ] content-type error")
									except:
										pass
								# 404
								else:
									pass
							except requests.exceptions.ReadTimeout:
								LOG.debug("Connection Timeout: "+siteURL)
							except requests.exceptions.ConnectTimeout:
								LOG.debug("Connection Timeout")
							except:
								err = sys.exc_info()
								LOG.error("Error: " + str(err))
								print("Error: " + str(err))
								pass
							# else:
							# 	pass
						else:
							pass
					else:
						pass
				# Ziplist empty
				else:
					pass
			except:
				err = sys.exc_info()
				LOG.error("DL Error: " + str(err))


		else:
			LOG.debug("["+str(r.status_code)+"] "+r.url)
			lastHTTPcode = str(r.status_code)
			SQL.SQLiteInvestigUpdateCode(InvTABLEname, siteURL, now, lastHTTPcode)
			SQL.SQLiteInsertStillTryDownload(TABLEname, siteURL)

	except requests.exceptions.ConnectionError:
		err = sys.exc_info()
		if '0x05: Connection refused' in err:
			SQL.SQLiteInvestigUpdateCode(InvTABLEname, siteURL, now, 'Conn. refused')
		if '0x04: Host unreachable' in err:
			SQL.SQLiteInvestigUpdateCode(InvTABLEname, siteURL, now, 'Unreachable')
		else:
			SQL.SQLiteInvestigUpdateCode(InvTABLEname, siteURL, now, 'Conn. error')
		SQL.SQLiteInsertStillTryDownload(TABLEname, siteURL)
		LOG.debug("Connection error: "+siteURL)

	except requests.exceptions.ConnectTimeout:
		SQL.SQLiteInvestigUpdateCode(InvTABLEname, siteURL, now, 'Conn. timeout')
		SQL.SQLiteInsertStillTryDownload(TABLEname, siteURL)
		LOG.debug("Connection Timeout: "+siteURL)

	except requests.exceptions.ReadTimeout:
		SQL.SQLiteInvestigUpdateCode(InvTABLEname, siteURL, now, 'Conn. readtimeout')
		SQL.SQLiteInsertStillTryDownload(TABLEname, siteURL)
		LOG.debug("Connection Read Timeout: "+siteURL)

	except requests.exceptions.MissingSchema:
		SQL.SQLiteInvestigUpdateCode(InvTABLEname, siteURL, now, 'Malformed URL')
		SQL.SQLiteInsertStillTryDownload(TABLEname, siteURL)
		LOG.debug("Malformed URL, skipping: "+siteURL+"\n")

	except:
		err = sys.exc_info()
		LOG.error("Error: " + str(err))


def RetriveIndexPath(url, proxies, headers, urllist=[]):
	domin = '/'.join(url.split('/')[0:3])
	try:
		r = requests.get(url, proxies=proxies, headers=headers, allow_redirects=True, timeout=(5,12), verify=False)
	except:
		pass
	else:
		soup = BeautifulSoup(r.text, 'html.parser')
		try:
			title = soup.title.text
		except:
			pass
		else:
			if 'Index of' in title:
				# Could be tracked
				res = soup.select('a')
				urllist += [url + x['href'] for x in res if '.zip' in x.text]
				urllist += [domin + x['href'] for x in res if '.zip' in x.text]
				folderlist = [url + x['href'] for x in res if (x['href'][-1] == '/') and (x.text != 'Parent Directory')]
				if len(folderlist) > 0:
					for folderUrl in folderlist:
						urllist = RetriveIndexPath(folderUrl, proxies, headers, urllist)
	return list(set(urllist))







