#!/usr/bin/python3
import email
import os.path
import time
from os import path
import uuid
from flask_jwt_extended import jwt_required, current_user, get_current_user
#from flask_jwt_extended import jwt_required, current_user, get_current_user, get_jwt_identity
from authorizenet import apicontractsv1
from authorizenet.apicontrollers import createTransactionController
from flask_jwt_extended import create_access_token
from flask_jwt_extended import JWTManager
import ast
from flask_httpauth import HTTPTokenAuth
from datetime import date, timedelta
from flask import Flask,redirect
from flask import g
import gzip
from flask_cors import CORS
import string
import re
from datetime import date, timedelta
import random
from flask_mail import Mail
from flask_mail import Message
from flask_autoindex import AutoIndex
from flask import Flask, render_template, send_from_directory, jsonify, send_file
from flask import Response
from flask import request
import json
import requests
import configparser
import sys
import datetime
import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from flask import make_response
import psycopg2
from jsondiff import diff
#from packageParser.pypiParser import pypi_parser
from celery import Celery
from celery.execute import send_task
from celery.result import AsyncResult
import uuid
from passive_api import get_json_feeds
import secrets
import tempfile
        
secrets.token_urlsafe(16)

mail = Mail()
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
#app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(seconds=3600)
#app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(seconds=3600)
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(seconds=3600)
app.config['SECURITY_PASSWORD_SALT'] = 'my_precious_two'
app.config["SECRET_KEY"] = "super-secret"

jwt = JWTManager(app)
app.config['JWT_TOKEN_LOCATION'] = ["headers"]
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!

CORS(app)

__all__ = ["getstatusoutput","getoutput","getstatus"]

def getstatus(file):
    """Return output of "ls -ld <file>" in a string."""
    import warnings
    warnings.warn("commands.getstatus() is deprecated", DeprecationWarning, 2)
    return getoutput('ls -ld' + mkarg(file))

def getoutput(cmd):
    """Return output (stdout or stderr) of executing cmd in a shell."""
    return getstatusoutput(cmd)[1]

def getstatusoutput(cmd):
    """Return (status, output) of executing cmd in a shell."""
    import os
    pipe = os.popen('{ ' + cmd + '; } 2>&1', 'r')
    text = pipe.read()
    sts = pipe.close()
    if sts is None: sts = 0
    if text[-1:] == '\n': text = text[:-1]
    return sts, text

def mk2arg(head, x):
    import os
    return mkarg(os.path.join(head, x))

def mkarg(x):
    if '\'' not in x:
        return ' \'' + x + '\''
    s = ' "'
    for c in x:
        if c in '\\$"`':
            s = s + '\\'
        s = s + c
    s = s + '"'
    return s

def get_vector(jsondata):

    keys = list(jsondata.keys())
    print(keys)

    for key in keys:
        if "CVE-" not in key:
            keys.remove(key)

    for key in keys:
        year = key.split("-")[1]
        # print(year)
        file_path = "nvd/cves/%s/%s.json" % (year, key)

        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                data = json.load(f)

            if 'impact' in data:
                if 'baseMetricV2' in data['impact']:
                    if 'cvssV2' in data['impact']['baseMetricV2']:
                        if 'accessVector' in data['impact']['baseMetricV2']['cvssV2']:
                            accessVector = data['impact']['baseMetricV2']['cvssV2']['accessVector']
                        else:
                            accessVector = "Unknown"
                    else:
                        accessVector = "Unknown"
                else:
                    accessVector = "Unknown"
            else:
                accessVector = "Unknown"

            jsondata[key]["accessVector"] = accessVector
        else:
            print("file not found")

    return jsondata


def get_dashboard_data(jsondata):

    # jsondata = get_vector(jsondata)

    output = {}
    output['chart'] = {}
    output['data'] = jsondata
    output['chart']['severity'] = {}
    output['chart']['platforms'] = {}
    output['chart']['ecosystems'] = {}
    output['chart']['accessVector'] = {}

    # SEVERITY
    severity_counts = {'HIGH': 0, 'MODERATE': 0, 'LOW': 0, 'CRITICAL': 0, 'UNKNOWN': 0}

    for item in jsondata.values():
        try:
            severity = item['severity']
            if severity in severity_counts:
                severity_counts[severity] += 1
        except:
            pass

    output['chart']['severity'] = severity_counts


    # ATTACK VECTOR
    vector_count = {'NETWORK': 0, 'LOCAL': 0, 'UNKNOWN': 0}
    for item in jsondata.values():
        print("zzzz",item)
        # try:
        if 'accessVector' in item:
            accessVector = item['accessVector']
        else:
            accessVector = ''
        
        print("......", accessVector)

        if accessVector in vector_count:
            vector_count[accessVector] += 1
        # except:
        #     pass

    output['chart']['accessVector'] = vector_count


    # VULNERABILITY
    platform_list = ["ubuntu", "debian", "oracle-linux", "suse-linux", "rhel"]
    
    for item in jsondata.values():
        ecosystem = item.get("ecosystem")

        print("---", ecosystem)

        if ecosystem in platform_list:
            output['chart']['platforms'][ecosystem] = output['chart']['platforms'].get(ecosystem, 0) + 1
        else:
            output['chart']['ecosystems'][ecosystem] = output['chart']['ecosystems'].get(ecosystem, 0) + 1


    return output




with open("credit_code_map.json", "r") as f:
    credit_map = json.load(f)

# Read config.ini file and load configuration.
settings = configparser.ConfigParser()
settings.read('config.ini')

settings = configparser.ConfigParser()
settings.read('config.cfg')
username = settings.get('rabbitmq', 'username')
password = settings.get('rabbitmq', 'password')
ipaddr = settings.get('rabbitmq', 'ipaddr')
vhost = settings.get('rabbitmq', 'vhost')


Celery('tasks', backend='amqp', broker='amqp://%s:%s@%s/%s' % (username, password, ipaddr, vhost))

@app.before_request
def db_connect():
    g.conn = psycopg2.connect(user="versa",password="versa123",host="127.0.0.1",port="5432",database="niahdb")
    g.cursor = g.conn.cursor()

@app.after_request
def db_disconnect(response):
    g.cursor.close()
    g.conn.close()
    return response

@app.teardown_appcontext
def close_conn(e):
    db = g.pop('db', None)
    if db is not None:
        app.config['postgreSQL_pool'].putconn(db)

@app.route('/api/userid', methods = ['GET'])
@jwt_required()
def getUserID():
    user_id = get_jwt_identity()
    return user_id

def getInvoice():
    query = "select inv_no, name from invoice_tab ORDER BY inv_no DESC LIMIT 1"
    g.cursor.execute(query)
    subDB = g.cursor.fetchall();

    if len(subDB) > 0:
        inv_no = subDB[0][0]
        inv_name = subDB[0][1]

        res = {}
        res['inv_no'] = inv_no
        return res
    else:
        res = {}
        res['inv_no'] = 1
        return res

# API to get subscription detail.
@app.route('/api/get/subscription', methods = ['GET'])
def getSubProfile():
    if request.method == 'GET':
        query = "select subscription_name, scans, users, modules, description from subscription_db"
        g.cursor.execute(query)
        subscribeDB = g.cursor.fetchall();

        results = []
        for pDB in subscribeDB:
            subscription_name = pDB[0]
            scans = pDB[1]
            users = pDB[2]
            modules = pDB[3]
            description = pDB[4]

            modules['scans'] = scans
            modules['users'] = users
            modules['subscription_name'] = subscription_name
            modules['description'] = description
            results.append(modules)

        return jsonify(results)

# API to get subscription data.
@app.route('/api/data/subscription', methods = ['GET'])
def getdataSubscription():
    if request.method == 'GET':
        query = "select type, number, amount from pricing_tab"
        g.cursor.execute(query)
        pricingDB = g.cursor.fetchall();

        results = []
        for pDB in pricingDB:
            stype = pDB[0]
            number = pDB[1]
            amount = pDB[2]
            
            if stype == "subscription":
                query = "select subscription_name from subscription_db where id='%s'" % (number)
                g.cursor.execute(query)
                subscribeDB = g.cursor.fetchall();

                for sDB in subscribeDB:
                    subscription_name = sDB[0]

                    res = {}
                    res['subscription_name'] = subscription_name
                    res['amount'] = amount
                    results.append(res)
            else:
                res = {}
                res['subscription_name'] = "NiahFlexi"

                query = "select numbers, discount from discount_tab where type='%s'" % stype
                g.cursor.execute(query)
                discountDB = g.cursor.fetchall();

                if len(discountDB) > 0:
                    for dDB in discountDB:
                        numbers = dDB[0]
                        discount = dDB[1]

                        res['discount'] = {}
                        res['discount'][stype] = {}
                        res['discount'][stype]['numbers'] = numbers
                        res['discount'][stype]['amount'] = discount

                if stype == "users":
                    res['amount'] = {}
                    res['amount']['users'] = {}
                    res['amount']['users']['number'] = number
                    res['amount']['users']['amount'] = amount

                if stype == "scans":
                    res['amount'] = {}
                    res['amount']['scans'] = {}
                    res['amount']['scans']['number'] = number
                    res['amount']['scans']['amount'] = amount
                
                results.append(res)

        return jsonify(results)


@app.route('/api/get/subscription', methods = ['POST'])
def getSubscription():
    if request.method == 'POST':
        req_data = request.get_json()        
        code = req_data['code']
        emailid = req_data['emailid']

        query = "select subscription, firstname, lastname, companyname, address, city, state, pincode, country, phone, status from subscription_db where emailid='%s' and code='%s'" % (emailid, code)
        g.cursor.execute(query)
        subscribeDB = g.cursor.fetchall();

        if len(subscribeDB) > 0:
            subscription = subscribeDB[0][0]
            firstname = subscribeDB[0][1]
            lastname = subscribeDB[0][2]
            companyname = subscribeDB[0][3]
            address = subscribeDB[0][4]
            city = subscribeDB[0][5]
            state = subscribeDB[0][6]
            pincode = subscribeDB[0][7]
            country = subscribeDB[0][8]
            phone = subscribeDB[0][9]
            status = subscribeDB[0][10]

            res = {}
            res['subscription'] = subscription
            res['firstname'] = firstname
            res['lastname'] = lastname
            res['companyname'] = companyname
            res['address'] = address
            res['city'] = city
            res['state'] = state
            res['pincode'] = pincode
            res['country'] = country
            res['phone'] = phone
            res['status'] = status
            res['error'] = False
        
            return jsonify(res)
        else:
            res = {}
            res['error'] = True
            return jsonify(res)

def check_license(email_id):
    query = "select status, code, subscription, user_id from license_master_db where emailid='%s'" % (email_id)
    g.cursor.execute(query)
    subscribeDB = g.cursor.fetchall();

    if len(subscribeDB) > 0:
        status = subscribeDB[0][0]
        code = subscribeDB[0][1]
        subscription = subscribeDB[0][2]
        user_id = subscribeDB[0][3]

        if status == "enable":
            res = {}
            res['status'] = status
            res['code'] = code
            res['subscription'] = subscription
            res['user_id'] = user_id
            return res
        else:
            res = {}
            res['status'] = status
            res['code'] = code
            res['subscription'] = subscription
            res['user_id'] = user_id
            return res
    else:
        return False

    
def check_license_from_api(email_id, api_key):
    query = "select status, code, subscription, user_id from license_master_db where emailid='%s' and api_key='%s'" % (email_id, api_key)
    g.cursor.execute(query)
    subscribeDB = g.cursor.fetchall();

    if len(subscribeDB) > 0:
        status = subscribeDB[0][0]
        code = subscribeDB[0][1]
        subscription = subscribeDB[0][2]
        user_id = subscribeDB[0][3]

        if status == "enable":
            res = {}
            res['status'] = status
            res['code'] = code
            res['subscription'] = subscription
            res['user_id'] = user_id
            return res
        else:
            res = {}
            res['status'] = status
            res['code'] = code
            res['subscription'] = subscription
            res['user_id'] = user_id
            return res
    else:
        return False

# API to subscribe user in niah service.
@app.route('/api/subscription/register', methods = ['POST', 'GET'])
def regSubscription():
    if request.method == 'POST':
        code = "123" # Auto Generate
        req_data = request.get_json()        
        firstname = req_data['firstname']
        lastname = req_data['lastname']
        companyname = req_data['companyname']
        city = req_data['city']
        state = req_data['state']
        pincode = req_data['pincode']
        phone = req_data['phone']
        country = req_data['country']
        emailid = req_data['emailid']
        address = req_data['address']

        if 'api_key' in req_data:
            api_key = req_data['api_key']
            res_sub = check_license_from_api(emailid, api_key)
            if res_sub:
                res = {}
                res['code'] = res_sub['code']
                res['subscription'] =  res_sub['subscription']
                if res_sub['status'] == "enable":
                    res['status'] = 1
                    res['error'] = "false"
                    res['message'] = "Subscription found activated"
                else:
                    res['status'] = 0
                    res['error'] = "false"
                    res['message'] = "Subscription Found deactivated"

                return jsonify(res)
            else:
                res = {}
                res['error'] = "true"
                res['message'] = "API KEY or EmailID Incorrect!! Please subscribe http://niahsecurity.io"
                return jsonify(res)

        if 'users' in req_data:
            users = req_data['users']
        else:
            users = 0

        if 'scans' in req_data:
            scans = req_data['scans']
        else:
            scans = 0
            
        subscription = req_data['subscription']

        if subscription == "Free":
            res_sub = check_license(emailid)
            
            if res_sub:
                res = {}
                res['code'] = res_sub['code']
                res['subscription'] =  res_sub['subscription']
                if res_sub['status'] == "enable":
                    res['status'] = 1
                    res['message'] = "Subscription found activated"
                else:
                    res['status'] = 0
                    res['message'] = "Subscription Found deactivated"
            else:
                user_id = uuid.uuid4()
                status, output = getstatusoutput("mkdir static/report/%s" % user_id)
                query = "insert into license_master_db(subscription, firstname, lastname, companyname, address, city, state, pincode, country, emailid, phone, code, status, user_id, users, scans) values('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 'disable', '%s', '%s', '%s');" % (subscription, firstname, lastname, companyname, address, city, state, pincode, country, emailid, phone, code, user_id, users, scans)
                print(query)
                g.cursor.execute(query)
                g.conn.commit()

                res = {}
                res['error'] = False
                res['user_id'] = user_id
                res['message'] = "Free Subscription Successfully Activated"
                return jsonify(res)
        else:
            res_sub = check_license(emailid)
            user_id = res_sub['user_id']

            if res_sub:
                query = "update license_master_db set subscription='%s', code='%s', users='%s', scans='%s', status='active' where emailid='%s'" % (subscription, code, users, scans, emailid) 
                print(query)
                g.cursor.execute(query)
                g.conn.commit()

                res = {}
                res['error'] = False
                res['user_id'] = user_id
                res['message'] = "Subscription Successfully Updated"
                return jsonify(res)

            else:
                user_id = uuid.uuid4()
                status, output = getstatusoutput("mkdir static/report/%s" % user_id)

                query = "insert into license_master_db(subscription, firstname, lastname, companyname, address, city, state, pincode, country, emailid, phone, code, status, user_id, users, scans) values('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 'disable', '%s', '%s', '%s');" % (subscription, firstname, lastname, companyname, address, city, state, pincode, country, emailid, phone, code, user_id, users, scans)
                print(query)
                g.cursor.execute(query)
                g.conn.commit()

                res = {}
                res['error'] = False
                res['user_id'] = user_id
                res['message'] = "Free Subscription Successfully Activated"
                return jsonify(res)

        return jsonify(res)

@app.route('/api/get/license', methods = ['POST'])
@jwt_required()
def updateSubCodeUpdate():
    user_id = get_jwt_identity()
    if request.method == 'POST':
        req_data = request.get_json()
        email_add = req_data['emailid']
        code = req_data['code']

        
        query = "select subscription, users, scans, code, status from license_master_db where emailid='%s' and code='%s'" % (email_add, code)
        g.cursor.execute(query)
        fetchData = g.cursor.fetchall()
        
        subscription = fetchData[0][0]
        users = fetchData[0][1]
        scans = fetchData[0][2]
        code = fetchData[0][3]
        status = fetchData[0][4]

        res = {}
        res['subscription'] = subscription
        res['users'] = users
        res['scans'] = scans
        res['code'] = code
        res['status'] = status

        return jsonify(res)

@app.route('/api/feed/update', methods = ['POST'])
def feedUpdate():
    if request.method == 'POST':
        req_data = request.get_json()
        code = req_data['code']
        feed_version = req_data['current_feed_version']

        query = "select version from feed_master_tab where pub_date='current'"
        print(query)
        g.cursor.execute(query)
        current_feed_data = g.cursor.fetchall()

        current_available_feed_version = current_feed_data[0][0]

        if feed_version == current_available_feed_version:
            res = {}
            res['message'] = "No update available"
            return jsonify(res)
        else:
            query = "select status from license_master_db where code='%s'" % code
            print(query)
            g.cursor.execute(query)
            history_data = g.cursor.fetchall()

            if len(history_data) > 0:
                if history_data[0][0] == "enable":
                    res = {}
                    res['current_available_feed_version'] = current_available_feed_version
                    res['message'] = "Current available feed version %s" % current_available_feed_version
                    return jsonify(res)
                else:
                    res = {}
                    res['message'] = "Licence is expired, please check"
                    return jsonify(res)
            else:
                res = {}
                res['message'] = "Licence is not found, please check"
                return jsonify(res)

# API to get Browse tab data in vulnerability DB page.
@app.route('/api/dash/browse', methods = ['GET'])
#@jwt_required()
def getdashBrowse():
    if request.method == 'GET':
        with open('/var/DB/feeds/browse/allcves.json') as f:
            advData = json.load(f)

        vulnerabilities = advData['vulnerabilities'][:10]
        products = advData['product'][:10]
        vendors = advData['vendor'][:10]

        results = {}
        results['data'] = []

        res = {}
        res['header'] = "By Vendor"
        res['title'] = "Top 10 vendors by vulnerability count"
        res['data'] = vendors
        res['column'] = [] 
        res['column'].append('totalvuln')
        res['column'].append('vendor')
        results['data'] .append(res)


        res = {}
        res['header'] = "By Product"
        res['title'] = "Top 10 products by vulnerability count"
        res['data'] = products
        res['column'] = [] 
        res['column'].append('totalvuln')
        res['column'].append('product')
        results['data'] .append(res)

        res = {}
        res['header'] = "By Vulnerability Type"
        res['title'] = "Top 10 vulnerability type count"
        res['data'] = vulnerabilities
        res['column'] = [] 
        res['column'].append('totalvuln')
        res['column'].append('name')
        results['data'] .append(res)

        return jsonify(results)

# API to get vulnerabilities details for specified filters.
@app.route('/api/vuln/list', methods=["GET"])
#@jwt_required()
def getdata():
    print("1 - %s" % request.args)
    if 'email_id' in request.args and 'code' in request.args:
        email_id = request.args.get('email_id')
        code = request.args.get('code')
    else:
        res = {}
        res['error'] = 1
        return jsonify(res)

    query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
    print(query)
    g.cursor.execute(query)
    status_data = g.cursor.fetchall()
    
    if len(status_data) > 0:
        if status_data[0][0] == "active":
            if request.args.get('offset'):
                pageoffset = request.args.get('offset')
                if request.args.get('limit'):
                    rowlimit = request.args.get('limit')
                else:
                    rowlimit = 50
            else:
                pageoffset = 0
                rowlimit = 50
                
            rowlimit = int(pageoffset) + int(rowlimit)

            results = {}

            results['columns'] = []

            resCol = {}
            resCol['title'] = "Vulnerability"
            resCol['field'] = "vulnerability"
            results['columns'].append(resCol)

            rescol = {}
            rescol['title'] = "baseScore(v2/v3)"
            rescol['field'] = "baseScore"
            results['columns'].append(rescol)

            resCol = {}
            resCol['title'] = "AccessVector(v2/v3)"
            resCol['field'] = "accessvector"
            results['columns'].append(resCol)

            resCol = {}
            resCol['title'] = "Severity(v2/v3)"
            resCol['field'] = "severity"
            results['columns'].append(resCol)

            resCol = {}
            resCol['title'] = "CWE"
            resCol['field'] = "cwe"
            results['columns'].append(resCol)

            resCol = {}
            resCol['title'] = "LastModified"
            resCol['field'] = "lastModifiedDate"
            results['columns'].append(resCol)

            f = open("/var/DB/feeds/nvd/vuln_feed.json", "r")
            jsonCVEsData = json.load(f)
            jsonData = jsonCVEsData

            results['total'] = len(jsonData)
            results['rowlimit'] = rowlimit

            results['results'] = jsonData[int(pageoffset):int(rowlimit)]

            return jsonify(results)
        else:
            res = {}
            res['error'] = 2
            return jsonify(res)
    else:
        res = {}
        res['error'] = 3
        return jsonify(res)

# APi to get home data in vulnerability DB page.
@app.route('/api/scan/home', methods = ['GET'])
def getHome():
    if request.method == 'GET':
        if request.args.get('type'):
            type = request.args.get('type')
        else:
            type = ''

        results = {}

        results['columns'] = []

        resCol = {}
        resCol['title'] = "Vulnerability"
        resCol['field'] = "vulnerability"
        results['columns'].append(resCol)

        rescol = {}
        rescol['title'] = "baseScore(v2/v3)"
        rescol['field'] = "baseScore"
        results['columns'].append(rescol)

        resCol = {}
        resCol['title'] = "AccessVector(v2/v3)"
        resCol['field'] = "accessvector"
        results['columns'].append(resCol)

        resCol = {}
        resCol['title'] = "Severity(v2/v3)"
        resCol['field'] = "severity"
        results['columns'].append(resCol)

        resCol = {}
        resCol['title'] = "CWE"
        resCol['field'] = "cwe"
        results['columns'].append(resCol)

        resCol = {}
        resCol['title'] = "LastModified"
        resCol['field'] = "lastModifiedDate"
        results['columns'].append(resCol)

        results['rowlimit'] = 50

        f = open("/var/DB/feeds/nvd/vuln_feed.json", "r")
        jsonCVEsData = json.load(f)
        jsonData = jsonCVEsData

        if request.args.get('year'):
            year = request.args.get('year')
            if year.lower() == "all":
                jsonData = jsonData
            else:
                jsonData = list(filter(lambda x: (year == x['year']), jsonData))

        if type == "product":
            if request.args.get('product'):
                product = request.args.get('product')
                jsonData = list(filter(lambda x: (product in x['products']), jsonData))

            if request.args.get('producttype'):
                producttype = request.args.get('producttype')

                if producttype == "os":
                    producttype = "o"
                if producttype == "application":
                    producttype = "a"
                if producttype == "hardware":
                    producttype = "h"

                jsonData = list(filter(lambda x: (producttype in x['part']), jsonData))

        if type == "vulnerabilities":
            if request.args.get('cweid'):
                cwe = "CWE-%s" % request.args.get('cweid')
                jsonData = list(filter(lambda x: (cwe in x['cwe'].split(",")), jsonData))

        if type == "vendor":
            if request.args.get('vendor'):
                vendor = request.args.get('vendor')
                jsonData = list(filter(lambda x: (vendor in x['vendors']), jsonData))

        if type == "language":
            if request.args.get('language'):
                language = request.args.get('language')
                jsonData = list(filter(lambda x: ('language' in x), jsonData))
                jsonData = list(filter(lambda x: (language in x['language']), jsonData))

        if type == "platform":
            if request.args.get('platform'):
                platform = request.args.get('platform')
                jsonData = list(filter(lambda x: ('family' in x), jsonData))
                jsonData = list(filter(lambda x: (platform in x['family']), jsonData))

        if type == "plugin":
            if request.args.get('plugin'):
                plugin = request.args.get('plugin')
                jsonData = list(filter(lambda x: ('plugin' in x), jsonData))
                jsonData = list(filter(lambda x: (plugin in x['plugin']), jsonData))

        if request.args.get('local') and request.args.get('remote'):
            jsonData = list(filter(lambda x: ('LOCAL' in x['accessvector'] or 'NETWORK' in x['accessvector']), jsonData))
        elif request.args.get('local'):
            jsonData = list(filter(lambda x: ('LOCAL' in x['accessvector']), jsonData))
        elif request.args.get('remote'):
            jsonData = list(filter(lambda x: ('NETWORK' in x['accessvector']), jsonData))

        if request.args.get('severity'):
            severity = request.args.get('severity')
            jsonData = list(filter(lambda x: (severity.upper() in x['severity'].upper()), jsonData))

        if request.args.get('offset'):
            pageoffset = request.args.get('offset')
            if request.args.get('limit'):
                rowlimit = request.args.get('limit')
            else:
                rowlimit = 50
        else:
            pageoffset = 0
            rowlimit = 50

        rowlimit = int(pageoffset) + int(rowlimit)
        results['rowlimit'] = rowlimit
        results['results'] = jsonData[int(pageoffset):int(rowlimit)]
        results['total'] = len(jsonData)

        return jsonify(results)


# APi to get specific product/vendor/vulnerability wise filter browse data in vulnerability page.
@app.route('/api/scan/browse', methods = ['GET'])
#@jwt_required()
def getBrowse():
    if request.method == 'GET':
        if request.args.get('type'):
            type = request.args.get('type')
        else:
            type = ''

        resRet = {}
        resRet['columns'] = []

        if type == "vulnerabilities":
            res = {}
            res['field'] = 'cwe_text'
            res['title'] = 'CWE'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'name'
            res['title'] = 'Vulnerability'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'severity'
            res['title'] = 'Severity'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'totalvuln'
            res['title'] = 'Total'
            resRet['columns'].append(res)
        
        if type == "product" or type == "":
            res = {}
            res['field'] = 'product'
            res['title'] = 'Product'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'vendor'
            res['title'] = 'Vendor'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'producttype'
            res['title'] = 'Producttype'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'severity'
            res['title'] = 'Severity'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'totalvuln'
            res['title'] = 'Total'
            resRet['columns'].append(res)

        if type == "vendor":
            res = {}
            res['field'] = 'vendor'
            res['title'] = 'Vendor'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'totalpackages'
            res['title'] = 'Total Packages'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'severity'
            res['title'] = 'Severity'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'totalvuln'
            res['title'] = 'Total'
            resRet['columns'].append(res)

        if request.args.get('year'):
            year = request.args.get('year')
        else:
            year = ''
            
        if type == "product":
            if request.args.get('producttype'):
                producttype = request.args.get('producttype')
                if producttype == "os":
                    producttype = "o"
                if producttype == "application":
                    producttype = "a"
                if producttype == "hardware":
                    producttype = "h"
            else:
                producttype = ''
            
            if request.args.get('product'):
                product = request.args.get('product')
            else:
                product = ''

        if request.args.get('offset'):
            pageoffset = request.args.get('offset')
            if request.args.get('limit'):
                rowlimit = request.args.get('limit')
            else:
                rowlimit = 50
        else:
            pageoffset = 0
            rowlimit = 50
        
        rowlimit = int(pageoffset) + int(rowlimit)

        resRet['rowlimit'] = rowlimit

        if year:
            with open('/var/DB/feeds/browse/%s.json' % year) as f:
                advData = json.load(f)
        else:	
            with open('/var/DB/feeds/browse/allcves.json') as f:
                advData = json.load(f)

        if type == "vulnerabilities":
            if request.args.get('cweid'):
                cweid = "CWE-%s" % request.args.get('cweid')
            else:
                cweid = ''
            
            if cweid:
                vulnerabilities = list(filter(lambda x: (x['cwe_text'] == cweid), advData['vulnerabilities']))
                resRet['results'] = vulnerabilities[int(pageoffset):int(rowlimit)]
                return jsonify(resRet)
            else:
                vulnerabilities = advData['vulnerabilities']
                resRet['results'] = vulnerabilities[int(pageoffset):int(rowlimit)]
                return jsonify(resRet)

        if type == "product":
            if producttype:
                products = list(filter(lambda x: (x['producttype'] == producttype), advData['product']))
            else:
                products = advData['product']

            if product:
                products = list(filter(lambda x: (x['product'] == product), products))

            resRet['results'] = products[int(pageoffset):int(rowlimit)]
            return jsonify(resRet)

        if type == "vendor":
            if request.args.get('vendor'):
                vendor = request.args.get('vendor')
            else:
                vendor = ''
            
            if vendor:
                vendors = list(filter(lambda x: (x['vendor'] == vendor), advData['vendor']))
                resRet['results'] = vendors[int(pageoffset):int(rowlimit)]
                return jsonify(resRet)
            else:
                vendors = advData['vendor']
                resRet['results'] = vendors[int(pageoffset):int(rowlimit)]
                return jsonify(resRet)    


# APi to get specific product/vendor/vulnerability wise filter browse data in vulnerability page.
@app.route('/api/v1/scan/browse', methods = ['GET'])
#@jwt_required()
def getv1Browse():
    if request.method == 'GET':
        if 'email_id' in request.args and 'code' in request.args:
            email_id = request.args.get('type')
            code = request.args.get('code')
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        if len(status_data) > 0:
            if status_data[0][0] == "active":        
                if request.args.get('type'):
                    type = request.args.get('type')
                else:
                    type = ''

                resRet = {}
                
                if request.args.get('year'):
                    year = request.args.get('year')
                else:
                    year = ''
                
                producttype = ''

                if type == "product":
                    if request.args.get('producttype'):
                        producttype = request.args.get('producttype')
                        if producttype == "os":
                            producttype = "o"
                        if producttype == "application":
                            producttype = "a"
                        if producttype == "hardware":
                            producttype = "h"
                    else:
                        producttype = ''
                    
                    if request.args.get('product'):
                        product = request.args.get('product')
                    else:
                        product = ''

                if request.args.get('offset'):
                    pageoffset = request.args.get('offset')
                    if request.args.get('limit'):
                        rowlimit = request.args.get('limit')
                    else:
                        rowlimit = 50
                else:
                    pageoffset = 0
                    rowlimit = 50
                
                rowlimit = int(pageoffset) + int(rowlimit)

                resRet['rowlimit'] = rowlimit

                if year:
                    with open('/var/DB/feeds/browse/%s.json' % year) as f:
                        advData = json.load(f)
                else:	
                    with open('/var/DB/feeds/browse/allcves.json') as f:
                        advData = json.load(f)

                if type == "vulnerabilities":
                    if request.args.get('cweid'):
                        cweid = "CWE-%s" % request.args.get('cweid')
                    else:
                        cweid = ''
                    
                    if cweid:
                        vulnerabilities = list(filter(lambda x: (x['cwe_text'] == cweid), advData['vulnerabilities']))
                        resRet['results'] = vulnerabilities[int(pageoffset):int(rowlimit)]
                        return jsonify(resRet)
                    else:
                        vulnerabilities = advData['vulnerabilities']
                        resRet['results'] = vulnerabilities[int(pageoffset):int(rowlimit)]
                        return jsonify(resRet)

                elif type == "product":
                    if producttype:
                        products = list(filter(lambda x: (x['producttype'] == producttype), advData['product']))
                    else:
                        products = advData['product']

                    if product:
                        products = list(filter(lambda x: (x['product'] == product), products))

                    resRet['results'] = products[int(pageoffset):int(rowlimit)]
                    return jsonify(resRet)

                elif type == "vendor":
                    if request.args.get('vendor'):
                        vendor = request.args.get('vendor')
                    else:
                        vendor = ''
                    
                    if vendor:
                        vendors = list(filter(lambda x: (x['vendor'] == vendor), advData['vendor']))
                        resRet['results'] = vendors[int(pageoffset):int(rowlimit)]
                        return jsonify(resRet)
                    else:
                        vendors = advData['vendor']
                        resRet['results'] = vendors[int(pageoffset):int(rowlimit)]
                        return jsonify(resRet)
                
                else:
                    resRet['results'] = advData['product'][int(pageoffset):int(rowlimit)]
                    return jsonify(resRet)
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)
        else:
            res = {}
            res['error'] = 3
            return jsonify(res)

# API to get platform feed data. (this API call by niah scanner and celery machine)
@app.route('/api/scan/platform/<platform>/<osname>', methods = ['POST', 'GET'])
#@jwt_required()
def getPlatform(platform, osname):
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['email_id']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1    
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        if len(status_data) > 0:
            if status_data[0][0] == "active":
                compression_level = 9
                with open("/var/DB/feeds/platform/%s_%s.json" % (platform, osname), "r") as f:
                    jsonData = json.load(f)

                content = gzip.compress(json.dumps(jsonData).encode('utf8'), compression_level)
                response = make_response(content)
                response.headers['Content-length'] = len(content)
                response.headers['Content-Encoding'] = 'gzip'
                return response
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)
        else:
            res = {}
            res['error'] = 3
            return jsonify(res)

def getnpm_javascript_mvers(product, version):
        response = requests.get('https://registry.npmjs.org/%s' % product)
        data = response.text
        data = json.loads(data)
        versionArray = data['versions']

        versions = []
        for ver in versionArray:
            versions.append(ver)

        return ' '.join(versions)


@app.route('/api/license/platform/<os_name>/<platform>', methods = ['POST', 'GET'])
#@jwt_required()
def getOSLicense(os_name, platform):
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['email_id']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        license_db = {}
        license_db_1 = ''
        license_db_2 = ''

        if len(status_data) > 0:
            if status_data[0][0] == "active": 
                if os_name == "ubuntu":               
                    with open("/var/DB/feeds/packages/ubuntu_license.json", "r") as f:
                        license_db_os = json.load(f)
                    
                    if platform in license_db_os['data']:
                        license_db_1 = license_db_os['data'][platform]

                    if "%s-updates" % platform in license_db_os['data']:
                        license_db_2 = license_db_os['data'][platform]

                    if license_db_1 or license_db_2:
                        license_db = {**license_db_1, **license_db_2}
                
                elif os_name == "debian":               
                    with open("/var/DB/feeds/packages/debian_license.json", "r") as f:
                        license_db_os = json.load(f)
                    
                    if platform in license_db_os['data']:
                        license_db_1 = license_db_os['data'][platform]

                    if "%s-backports" % platform in license_db_os['data']:
                        license_db_2 = license_db_os['data'][platform]

                    if license_db_1 or license_db_2:
                        license_db = {**license_db_1, **license_db_2}
                else:
                    license_db = {}

        return jsonify(license_db) 


@app.route('/api/license/language/<application>', methods = ['POST', 'GET'])
#@jwt_required()
def getLicense(application):
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['email_id']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        license_db = {}

        if len(status_data) > 0:
            if status_data[0][0] == "active": 
                if application == "javascript":               
                    with open("/var/DB/feeds/packages/npm_license.json", "r") as f:
                        license_db = json.load(f)
                elif application == "python":               
                    with open("/var/DB/feeds/packages/pypi_license.json", "r") as f:
                        license_db = json.load(f)
                elif application == "php":               
                    with open("/var/DB/feeds/packages/composer_license.json", "r") as f:
                        license_db = json.load(f)
                elif application == "java":               
                    with open("/var/DB/feeds/packages/maven_license.json", "r") as f:
                        license_db = json.load(f)
                else:
                    license_db = {}

        return jsonify(license_db)        

# API to get specified language (python/php/java/javascript) products feeds. (this API call by niah scanner and celery machine)
@app.route('/api/scan/language/<application>', methods = ['POST', 'GET'])
#@jwt_required()
def getLanguage(application):
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['email_id']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        if len(status_data) > 0:
            if status_data[0][0] == "active":                
                productLists = req_data['data']

                res = {}
                res['results'] = []

                productLists = productLists.split(",")

                with open("/var/DB/feeds/language/%s.json" % application, "r") as f:
                    jsonData = json.load(f)
                    
                jsonDataArray = jsonData['data']
                for p in productLists:
                    product = p.strip()
                    jsonData = list(filter(lambda x: (x['product'] == product), jsonDataArray))

                    if len(jsonData) > 0:
                        for d in jsonData:
                            if application == "javascript":
                                d['available_versions'] = getnpm_javascript_mvers(d['product'], d['version'])
                            else:
                                d['available_versions'] = ''
                            res['results'].append(d)
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)
        else:
            res = {}
            res['error'] = 3
            return jsonify(res)
        
        return res

# API to get specified language (python/php/java/javascript) products feeds. (this API call by niah scanner and celery machine) (This API also match vendor)
@app.route('/api/scan/vendor/language/<application>', methods = ['POST', 'GET'])
#@jwt_required()
def getVendorLanguage(application):
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['email_id']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        if len(status_data) > 0:
            if status_data[0][0] == "active":        
                productLists = req_data['data']

                res = {}
                res['results'] = {}

                productLists = productLists.split(",")

                with open("/var/DB/feeds/language/%s.json" % application, "r") as f:
                    jsonData = json.load(f)
                    
                jsonDataArray = jsonData['data']

                for p in productLists:
                    product = p.split('/')[1]
                    vendor = p.split('/')[0]

                    jsonData = list(filter(lambda x: (x['product'] == product), jsonDataArray))

                    if vendor:
                        jsonData = list(filter(lambda x: (x['vendor'] == vendor), jsonData))

                    if len(jsonData) > 0:
                        if product not in res['results']:
                            res['results'][product] = []

                        for d in jsonData:
                            res['results'][product].append(d)
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)
        else:
            res = {}
            res['error'] = 3
            return jsonify(res)

        return res

# API to fetch Plugins vulnerabilities details. (This API is call by niah scanner and celery machine)
@app.route('/api/scanDetailsPlugin/<application>', methods = ['POST', 'GET'])
@jwt_required()
def getProductVersionPlugin(application):
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['email_id']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        if len(status_data) > 0:
            if status_data[0][0] == "active":
                productLists = req_data['data']

                res = {}
                res['results'] = {}
                productLists = productLists.split(",")

                for product in productLists:
                    jsonData = list(filter(lambda x: (x['product'] == product), jsonData))
                    if len(jsonData) > 0:
                        if product not in res['results']:
                            res['results'][product] = []

                        for d in jsonData:
                            res['results'][product].append(d)

                return res
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)
        else:
            res = {}
            res['error'] = 3
            return jsonify(res)


# API to fetch applications vulnerabilities details. (This API is call by niah scanner and celery machine)
@app.route('/api/vulnapp', methods = ['POST', 'GET'])
@jwt_required()
def getappdb():
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['email_id']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        if len(status_data) > 0:
            if status_data[0][0] == "active":
                productLists = req_data['data']

                with open("/var/DB/feeds/application/application.json", "r") as f:
                    jsonData = json.load(f)

                jsonDataArray = jsonData['data']

                results = {}
                for product in productLists.split(","):
                    product = product.lower()
                    if product not in results:
                        results[product] = []

                    jsonData = list(filter(lambda x: (x['product'] == product), jsonDataArray))
                
                    if len(jsonData) > 0:
                        for row in jsonData:
                            if row not in results[product]:
                                results[product].append(row)
                return results
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)

        else:
            res = {}
            res['error'] = 3
            return jsonify(res)


# API to get CVE details (This is authentication API which is available after login, and we handle alert detail of specified CVE)
@app.route('/api/auth/cve', methods=["GET"])
#@jwt_required()
def cveSearchAuth():
    if 'email_id' in request.args and 'code' in request.args:
        email_id = request.args.get('email_id')
        code = request.args.get('code')
    else:
        res = {}
        res['error'] = 1
        return jsonify(res)
    
    query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
    print(query)
    g.cursor.execute(query)
    status_data = g.cursor.fetchall()
        
    if len(status_data) > 0:
        if status_data[0][0] == "active":
            user_id = email_id
            if request.args.get('cve'):
                cve_id = request.args.get('cve')
                
                if path.exists("/var/DB/CVEs/%s.json" % (cve_id)):
                    with open("/var/DB/CVEs/%s.json" % (cve_id)) as f:
                        results = json.load(f)
                else:
                    results = {}
                    results['Products'] = {}
                    results['microsoft_advisory'] = {}
                    results['platform_advisory'] = {}
                    results['library_advisory'] = {}
                    results['plugin_advisory'] = {}
                    results['application_advisory'] = {}
                
                retRes = results

                retRes['Products']['title'] = "NVD Products"
                retRes['Products']['columns'] = []

                resCol = {}
                resCol['title'] = "Product"
                resCol['field'] = "product"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "Vendor"
                resCol['field'] = "vendor"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "Versions"
                resCol['field'] = "version"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "Patch"
                resCol['field'] = "patch"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "Part"
                resCol['field'] = "type"
                retRes['Products']['columns'].append(resCol)

                
                if 'microsoft_advisory' in retRes:
                    retRes['microsoft_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "KB Artical"
                    resCol['field'] = "KBArtical"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Article Url"
                    resCol['field'] = "articleUrl"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Download Name"
                    resCol['field'] = "downloadName"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Download Url"
                    resCol['field'] = "DownloadUrl"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Supercedence KB"
                    resCol['field'] = "supercedence"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "Product"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Platform"
                    resCol['field'] = "Platform"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Publish Date"
                    resCol['field'] = "PublishDate"
                    retRes['microsoft_advisory']['columns'].appen(resCol)


                if 'platform_advisory' in retRes:
                    retRes['platform_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Package"
                    resCol['field'] = "product"
                    retRes['platform_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Platform"
                    resCol['field'] = "platform"
                    retRes['platform_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Advisory"
                    resCol['field'] = "advisoryid"
                    retRes['platform_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Patch"
                    resCol['field'] = "patch"
                    retRes['platform_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Family"
                    resCol['field'] = "family"
                    retRes['platform_advisory']['columns'].append(resCol)

                if 'library_advisory' in retRes:
                    retRes['library_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "product"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Vendor"
                    resCol['field'] = "vendor"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Versions"
                    resCol['field'] = "version"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Patch"
                    resCol['field'] = "patch"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Language"
                    resCol['field'] = "language"
                    retRes['library_advisory']['columns'].append(resCol)
        

                if 'plugin_advisory' in retRes:
                    retRes['plugin_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "product"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Vendor"
                    resCol['field'] = "vendor"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Versions"
                    resCol['field'] = "versions"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Patch"
                    resCol['field'] = "patch"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Application"
                    resCol['field'] = "application"
                    retRes['plugin_advisory']['columns'].append(resCol)


                if 'application_advisory' in retRes:
                    retRes['application_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "product"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Vendor"
                    resCol['field'] = "vendor"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Versions"
                    resCol['field'] = "versions"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Patch"
                    resCol['field'] = "patch"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Application"
                    resCol['field'] = "application"
                    retRes['application_advisory']['columns'].append(resCol)
                
                retRes['alert'] = False

                return jsonify(retRes)
            else:
                retRes = {}
                retRes['error'] = True
                retRes['message'] = "Argument cve is require"
                return jsonify(retRes)
        else:
            res = {}
            res['error'] = 2
            return jsonify(res)
    else:
        res = {}
        res['error'] = 3
        return jsonify(res)

# API to get CVE details (This is authentication API which is available after login, and we handle alert detail of specified CVE)
@app.route('/api/v1/auth/cve', methods=["GET"])
#@jwt_required()
def cvev1SearchAuth():
    if 'email_id' in request.args and 'code' in request.args:
        email_id = request.args.get('type')
        code = request.args.get('code')
    else:
        res = {}
        res['error'] = 1
        return jsonify(res)
    
    query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
    print(query)
    g.cursor.execute(query)
    status_data = g.cursor.fetchall()
        
    if len(status_data) > 0:
        if status_data[0][0] == "active":
            user_id = email_id
            if request.args.get('cve'):
                cve_id = request.args.get('cve')
                
                if path.exists("/var/DB/CVEs/%s.json" % (cve_id)):
                    with open("/var/DB/CVEs/%s.json" % (cve_id)) as f:
                        results = json.load(f)
                else:
                    results = {}
                
                retRes = results

                retRes['alert'] = False
                
                return jsonify(retRes)
            else:
                retRes = {}
                retRes['error'] = True
                retRes['message'] = "Argument cve is require"
                return jsonify(retRes)
        else:
            res = {}
            res['error'] = 2
            return jsonify(res)
    else:
        res = {}
        res['error'] = 3
        return jsonify(res)

# API to get specified plugin vulnerability details. (this API call by niah scanner or celery machine)
@app.route('/api/plugin/<application>', methods = ['POST', 'GET'])
@jwt_required()
def getcmsdb(application):
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['email_id']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
            
        if len(status_data) > 0:
            if status_data[0][0] == "active":
                productLists = req_data['data']

                results = {}

                with open("/var/DB/feeds/plugins/%s_plugins.json" % application , "r") as f:
                    jsonData = json.load(f)

                jsonDataArray = jsonData['data']

                for product in productLists.split(","):
                    if product not in results:
                        results[product] = []

                    jsonData = list(filter(lambda x: (x['product'] == product), jsonDataArray))
            
                    for aDB in jsonData:
                        if aDB not in results[product]:
                            results[product].append(aDB)

                return results
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)
        else:
            res = {}
            res['error'] = 3
            return jsonify(res)
        

# This is product vulnerabilities details lists API. 
@app.route('/api/details/product', methods = ['POST', 'GET'])
def getDetails():
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['email_id']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
            
        if len(status_data) > 0:
            if status_data[0][0] == "active":
                type = req_data['type']
                application = req_data['application']
                product = req_data['product']

                results = {}
                results['header'] = []

                res = {}
                res['product'] = product
                results['header'].append(res)

                res = {}
                res['type'] = application
                results['header'].append(res)

                if type == "dependencies" or type == "language":
                    with open("/var/DB/feeds/language/language.json", "r") as f:
                        jsonData = json.load(f)
                    jsonData = jsonData['data']
                    jsonData = list(filter(lambda x: (x['language'] == application), jsonData))
                    jsonData = list(filter(lambda x: (x['product'] == product), jsonData))

                if type == "platform" or type == "system":
                    with open("/var/DB/feeds/platform/%s.json" % application, "r") as f:
                        jsonData = json.load(f)
                    jsonData = jsonData['data']
                    jsonData = list(filter(lambda x: (x['product'] == product), jsonData))

                if type == "plugin":
                    with open("/var/DB/feeds/plugin/plugin.json", "r") as f:
                        jsonData = json.load(f)
                    jsonData = jsonData['data']
                    jsonData = list(filter(lambda x: (x['application'] == application), jsonData))
                    jsonData = list(filter(lambda x: (x['product'] == product), jsonData))

                if type == "application":
                    with open("/var/DB/feeds/application/application.json", "r") as f:
                        jsonData = json.load(f)
                    jsonData = jsonData['data']
                    jsonData = list(filter(lambda x: (x['product'].lower() == product.lower()), jsonData))

                res = {}
                res['total_vuln'] = len(jsonData)
                results['header'].append(res)
                    
                results['db'] = {}
                results['db']['columns'] = []
                results['db']['results'] = []

                res = {}
                res['title'] = "Vulnerability"
                res['field'] = "vulnerability"
                results['db']['columns'].append(res)

                res = {}
                res['title'] = "PublishDate"
                res['field'] = "publish_date"
                results['db']['columns'].append(res)

                res = {}
                res['title'] = "VectorString"
                res['field'] = "vectorstring"
                results['db']['columns'].append(res)

                res = {}
                res['title'] = "Severity"
                res['field'] = "severity"
                results['db']['columns'].append(res)

                res = {}
                res['title'] = "CWE"
                res['field'] = "cwe_text"
                results['db']['columns'].append(res)

                res = {}
                res['title'] = "Versions"
                res['field'] = "versions"
                results['db']['columns'].append(res)

                res = {}
                res['title'] = "Patch"
                res['field'] = "patch"
                results['db']['columns'].append(res)

                res = {}
                res['title'] = "attackVector"
                res['field'] = "attackVector"
                results['db']['columns'].append(res)

                tempCWE = {}
                tempSeverity = {}
            
                for aDB in jsonData:
                    results['db']['results'].append(aDB)
                    
                    cwe_text = aDB['cwe_text']

                    if cwe_text not in tempCWE:
                        tempCWE[cwe_text] = []

                    tempCWE[cwe_text].append(res)

                    if aDB['severityV3']:
                        severity = aDB['severityV3']
                    elif aDB['severityV2']:
                        severity = aDB['severityV2']
                    else:
                        severity = "UNKNOWN"

                    if severity not in tempSeverity:
                        tempSeverity[severity] = []
                        
                    tempSeverity[severity].append(res)
                    
                results['chart'] = {}
                results['chart']['cwe'] = {}
                results['chart']['severity'] = {}

                for cweId in tempCWE:
                    results['chart']['cwe'][cweId] = len(tempCWE[cweId])
                    
                for severity in tempSeverity:
                    results['chart']['severity'][severity] = len(tempSeverity[severity])
        
                return jsonify(results)
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)
        else:
            res = {}
            res['error'] = 3
            return jsonify(res)
            

# API to get CVE detail. (this is unauthentication API, which is call on main page.)
@app.route('/api/cve', methods=["GET"])
def cveSearch():
    if 'email_id' in request.args and 'code' in request.args:
        email_id = request.args.get('type')
        code = request.args.get('code')
    else:
        res = {}
        res['error'] = 1
        return jsonify(res)
    
    query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
    print(query)
    g.cursor.execute(query)
    status_data = g.cursor.fetchall()
        
    if len(status_data) > 0:
        if status_data[0][0] == "active":
            search_text = ''
            if request.args.get('cve'):
                cve_id = request.args.get('cve')

                year = cve_id.split("-")[1]

                if path.exists("/var/DB/CVEs/%s/%s.json" % (year, cve_id)):
                    with open("/var/DB/CVEs/%s/%s.json" % (year, cve_id)) as f:
                        results = json.load(f)
                else:
                    results = {}
                    retRes['Products'] = {}
                    retRes['microsoft_advisory'] = {}
                    retRes['platform_advisory'] = {}
                    retRes['library_advisory'] = {}
                    retRes['plugin_advisory'] = {}
                    retRes['application_advisory'] = {}


                retRes = results
                search_text = 'cve_id="%s"' % cve_id

                retRes['Products']['columns'] = []
                    
                resCol = {}
                resCol['title'] = "Product"
                resCol['field'] = "product"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "Vendor"
                resCol['field'] = "vendor"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "Versions"
                resCol['field'] = "version"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "patch"
                resCol['field'] = "patch"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "Part"
                resCol['field'] = "type"
                retRes['Products']['columns'].append(resCol)

                if 'microsoft_advisory' in retRes:
                    retRes['microsoft_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "KB Artical"
                    resCol['field'] = "KBArtical"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Article Url"
                    resCol['field'] = "articleUrl"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Download Name"
                    resCol['field'] = "downloadName"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Download Url"
                    resCol['field'] = "DownloadUrl"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Supercedence KB"
                    resCol['field'] = "supercedence"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "Product"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Platform"
                    resCol['field'] = "Platform"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Publish Date"
                    resCol['field'] = "pub_date"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                if 'platform_advisory' in retRes:
                    retRes['platform_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Platform"
                    resCol['field'] = "Platform"
                    retRes['platform_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Reference"
                    resCol['field'] = "Reference"
                    retRes['platform_advisory']['columns'].append(resCol)

                if 'library_advisory' in retRes:
                    retRes['library_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "product"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Vendor"
                    resCol['field'] = "vendor"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Versions"
                    resCol['field'] = "version"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Patch"
                    resCol['field'] = "patch"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Language"
                    resCol['field'] = "language"
                    retRes['library_advisory']['columns'].append(resCol)

                if 'plugin_advisory' in retRes:
                    retRes['plugin_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "product"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Vendor"
                    resCol['field'] = "vendor"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Versions"
                    resCol['field'] = "versions"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Patch"
                    resCol['field'] = "patch"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Application"
                    resCol['field'] = "application"
                    retRes['plugin_advisory']['columns'].append(resCol)

                if 'application_advisory' in retRes:
                    retRes['application_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "product"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Vendor"
                    resCol['field'] = "vendor"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Versions"
                    resCol['field'] = "versions"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Patch"
                    resCol['field'] = "patch"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Application"
                    resCol['field'] = "application"
                    retRes['application_advisory']['columns'].append(resCol)
                                    
                return jsonify(retRes)
            else:
                res = {}
                res['error'] = True
                res['message'] = "Argument cve is require"
                return jsonify(retRes)
        else:
            res = {}
            res['error'] = 2
            return jsonify(res)
    else:
        res = {}
        res['error'] = 3
        return jsonify(res)


# This API is to search CVEs details.
@app.route('/api/search/cve', methods=["GET"])
def cveWiseSearch():
    if request.method == 'GET':
        search_text = ''
        cve_id = ''

        if request.args.get('cve'):
            cve_id = request.args.get('cve')
            year = cve_id.split("-")[1]
        
            retRes = {}
            retRes['severity'] = {}
            retRes['snapshot'] = {}
            retRes['NIAH_Insights'] = []
            retRes['niah_meter'] = {}

            if path.exists("/var/DB/CVEs/%s.json" % (cve_id)):
                with open("/var/DB/CVEs/%s.json" % (cve_id), "r") as f:
                    results = json.load(f)
            else:
                results = {}
            
            dr_products_info = []
            dr_vendors_info = []
            dr_family_info = []
            dr_language_info = []
            dr_plugin_info = []
            dr_platform_info = []
            dr_microsoft_info = []
            
            jsonCVEsData = {}
            jsonCVEsData[year] = {}
            jsonCVEsData[year][cve_id] = results

            if 'description' in jsonCVEsData[year][cve_id]:
                retRes['snapshot']['Description'] = jsonCVEsData[year][cve_id]['description']
            else:
                retRes['snapshot']['Description'] = ''
            if 'CWE' in jsonCVEsData[year][cve_id]:
                retRes['snapshot']['CWEID'] = jsonCVEsData[year][cve_id]['CWE'] 
            if 'publishedDate' in jsonCVEsData[year][cve_id]:
                retRes['snapshot']['publishedDate'] = jsonCVEsData[year][cve_id]['publishedDate']
            else:
                retRes['snapshot']['publishedDate'] = ''

            if 'plugin_advisory' in jsonCVEsData[year][cve_id]:
                retRes['plugin_advisory'] = jsonCVEsData[year][cve_id]['plugin_advisory']['data']
                for plgVuln in jsonCVEsData[year][cve_id]['plugin_advisory']['data']:
                    if plgVuln['product'] not in dr_products_info:
                        dr_products_info.append(plgVuln['product'])
                    if plgVuln['vendor'] not in dr_vendors_info:
                        dr_vendors_info.append(plgVuln['vendor'])
                    if plgVuln['plugin'] not in dr_plugin_info:
                        dr_plugin_info.append(plgVuln['plugin'])

            if 'application_advisory' in jsonCVEsData[year][cve_id]:
                retRes['application_advisory'] = jsonCVEsData[year][cve_id]['application_advisory']['data']
                for appVuln in jsonCVEsData[year][cve_id]['application_advisory']['data']:
                    if appVuln['product'] not in dr_products_info:
                        dr_products_info.append(appVuln['product'])
                    if appVuln['vendor'] not in dr_vendors_info:
                        dr_vendors_info.append(appVuln['vendor'])

            if 'library_advisory' in jsonCVEsData[year][cve_id]:
                retRes['library_advisory'] = jsonCVEsData[year][cve_id]['library_advisory']['data']
                for langVuln in jsonCVEsData[year][cve_id]['library_advisory']['data']:
                    if langVuln['product'] not in dr_products_info:
                        dr_products_info.append(langVuln['product'])
                    if langVuln['language'] not in dr_language_info:
                        dr_language_info.append(langVuln['language']) 
                    if langVuln['vendor'] not in dr_vendors_info:
                        dr_vendors_info.append(langVuln['vendor'])

            if 'platform_advisory' in jsonCVEsData[year][cve_id]:
                retRes['platform_advisory'] = jsonCVEsData[year][cve_id]['platform_advisory']['data']
                for plvuln in jsonCVEsData[year][cve_id]['platform_advisory']['data']:
                    if plvuln['product'] not in dr_products_info:
                        dr_products_info.append(plvuln['product'])
                    if plvuln['family'] not in dr_family_info:
                        dr_family_info.append(plvuln['family'])
                    if plvuln['platform'] not in dr_platform_info:
                        dr_platform_info.append(plvuln['platform'])
                    if plvuln['vendor'] not in dr_vendors_info:
                        dr_vendors_info.append(plvuln['vendor'])

            if 'microsoft_advisory' in jsonCVEsData[year][cve_id]:
                retRes['microsoft_advisory'] = jsonCVEsData[year][cve_id]['microsoft_advisory']['data']

            if 'CVSS20' in jsonCVEsData[year][cve_id]:
                if 'baseScore' in jsonCVEsData[year][cve_id]['CVSS20']:
                    retRes['severity']['CVSS 2.0'] = jsonCVEsData[year][cve_id]['CVSS20']['baseScore']
                else:
                    retRes['severity']['CVSS 2.0'] = ''

            if 'CVSS30' in jsonCVEsData[year][cve_id]:
                if 'baseScore' in jsonCVEsData[year][cve_id]['CVSS30']:
                    retRes['severity']['CVSS 3.0'] = jsonCVEsData[year][cve_id]['CVSS30']['baseScore']
                else:
                    retRes['severity']['CVSS 3.0'] = ''

            if 'cwe_str' in jsonCVEsData[year][cve_id]:
                CWEStr = jsonCVEsData[year][cve_id]['cwe_str']
            else:
                CWEStr = ''

            dr_info_json = jsonCVEsData[year][cve_id]['Products']['data']
            
            for advvuln in dr_info_json:
                if advvuln['vendor'] == "microsoft":
                    if advvuln['product'] not in dr_microsoft_info:
                        dr_microsoft_info.append(advvuln['product'])
                    if advvuln['vendor'] not in dr_vendors_info:
                        dr_vendors_info.append(advvuln['vendor'])
                    
            if len(dr_info_json) > 0:
                for dr_info in dr_info_json:
                    if 'products' in dr_info:
                        if dr_info['product'] not in dr_products_info:
                            dr_products_info.append(dr_info['product'])
                    if 'vendors' in dr_info:
                        if dr_info['vendors'] not in dr_vendors_info:
                            dr_vendors_info.append(dr_info['vendors'])
                    if 'family' in dr_info:
                        if dr_info['family'] not in dr_family_info:
                            dr_family_info.append(dr_info['family'])
                    if 'language' in dr_info:
                        if dr_info['language'] not in dr_language_info:
                            dr_language_info.append(dr_info['language'])
                    if 'plugin' in dr_info:
                        if dr_info['plugin'] not in dr_plugin_info:
                            dr_plugin_info.append(dr_info['plugin'])
                    if 'platform' in dr_info:
                        if dr_info['platform'] not in dr_platform_info:
                            dr_platform_info.append(dr_info['platform'])


            if CWEStr and CWEStr != "None":
                retRes['NIAH_Insights'].append("This is %s vulnerability" % CWEStr)
            if 'microsoft_advisory' in jsonCVEsData[year][cve_id]:
                retRes['NIAH_Insights'].append("There are %s Microsoft KBs published for this vulnerability" % len(jsonCVEsData[year][cve_id]['microsoft_advisory']['data']))
            if 'Exploits' in jsonCVEsData[year][cve_id]:
                if len(jsonCVEsData[year][cve_id]['Exploits']) > 0:
                    retRes['NIAH_Insights'].append("There are %s public exploits published for this vulnerability" % len(jsonCVEsData[year][cve_id]['Exploits']))
            
            if dr_platform_info:
                retRes['NIAH_Insights'].append("There are %s linux platform are found vulnerable. (%s)" % (len(dr_platform_info), ', '.join(dr_platform_info)))
            if dr_plugin_info:
                retRes['NIAH_Insights'].append("There are %s plugins are vulnerable. (%s)" % (len(dr_plugin_info), ', '.join(dr_plugin_info)))
            if dr_language_info:
                retRes['NIAH_Insights'].append("There are %s dependencies found vulnerable. (%s)" % (len(dr_language_info), ', '.join(dr_language_info)))
            if dr_family_info:
                retRes['NIAH_Insights'].append("There are %s family are vulnerable. (%s)" % (len(dr_family_info), ', '.join(dr_family_info)))
            if dr_vendors_info:
                retRes['NIAH_Insights'].append("There are %s vendor are vulnerable." % (len(dr_vendors_info)))
            if dr_products_info:
                retRes['NIAH_Insights'].append("There are %s products are vulnerable." % (len(dr_products_info)))


            retRes['niah_meter']['title'] = "Niah Worry Meter"
            retRes['niah_meter']['patch_now'] = "http://web.niahsecurity.io/"
            retRes['niah_meter']['speedometer'] = {}
            retRes['niah_meter']['speedometer']['min'] = "0"
            retRes['niah_meter']['speedometer']['max'] = "10"
            retRes['niah_meter']['speedometer']['default'] = "5"
            retRes['niah_meter']['segments'] = [0,4,6,10]
            retRes['niah_meter']['colors'] = ["#ff5355","#efd514","#3ccc5b"]
                                    
            return jsonify(retRes)
        else:
            res = {}
            res['error'] = True
            res['message'] = "Argument cve is require"
            return jsonify(retRes)

# Get Application.config file. This file is required for application scannning to get meta details of application like (application name, application version regex, application version file location).
@app.route('/api/getConfig')
def getAppConfig():
    with open("application.config") as f:
        configData = json.load(f)

    resRet = {}
    resRet['details'] = []
    return configData

def check_user_active(user_id):
    query = "select status from license_master_db where user_id='%s'" % user_id
    print(query)
    g.cursor.execute(query)
    fdata = g.cursor.fetchall()

    if len(fdata) > 0:
        if fdata[0][0] == "enable":
            return True
        else:
            return False
    else:
        return False

def get_user_id(api_key):
    query = "select user_id from license_master_db where api_key='%s'" % api_key
    print(query)
    g.cursor.execute(query)
    fdata = g.cursor.fetchall()

    if len(fdata) > 0:
        user_id = fdata[0][0]
        return user_id
    else:
        return False

def updateCounter(type, dst_ip, user_id, api_type, filename):
    now = datetime.datetime.now()
    date1 = now.strftime("%Y_%m_%d_%H_%M_%S")
    

    if api_type in credit_map:
        credit = credit_map[api_type]
    else:
        credit = 0

    query = "insert into counter_tab(type, credit, date1, dst_ip, user_id, api_type, reportname) values('%s', '%s', '%s', '%s', '%s', '%s','%s')" % (type, credit, date1, dst_ip, user_id, api_type, filename)
    print(query)
    g.cursor.execute(query)
    g.conn.commit()


    return True

@app.route('/api/v1/generate/key', methods = ['GET'])
def gen_api_key():
    if request.method == 'GET':
        req_data = request.get_json()
        user_id = req_data['user_id']
        api_key = secrets.token_hex(16)

        query = "update license_master_db set api_key='%s' where user_id='%s'" % (api_key, user_id)
        print(query)
        g.cursor.execute(query)
        g.conn.commit()
        
        res = {}
        res['api_key'] = api_key
        res['user_id'] = user_id

        return jsonify(res)

@app.route('/api/check/license', methods = ['POST', 'GET'])
def checkLicense(type):
    if request.method == 'POST':
        req_data = request.get_json()
        email_id = req_data['email_id']
        code = req_data['code']

        query = "select status from license_master_db where emailid='%s' and code='%s'" % (email_id, code)
        print(query)
        g.cursor.execute(query)
        fdata = g.cursor.fetchall()

        if len(fdata) > 0:
            if fdata[0][0] == "active":
                res = {}
                res['status'] = 1
            else:
                res = {}
                res['status'] = 0
        else:
            res = {}
            res['status'] = 0

        return jsonify(res)

@app.route('/api/v1/dependency/<name>', methods = ['POST', 'GET'])
def get_dependency(name):
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['email_id']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        if request.args.get('offset'):
            pageoffset = request.args.get('offset')
            if request.args.get('limit'):
                rowlimit = request.args.get('limit')
            else:
                rowlimit = 50
        else:
            pageoffset = 0
            rowlimit = 50

        jsondata = {}

        if len(status_data) > 0:
            if status_data[0][0] == "active": 
                if os.path.exists("/var/DB/feeds/language/%s.json" % name):
                    with open("/var/DB/feeds/language/%s.json" % name, "r") as f:
                        jsondata = json.load(f)['results']

        with open("/var/DB/feeds/language/%s.json" % name, "r") as f:
            jsondata = json.load(f)['results']

        jsondata.sort(key=lambda x: x["modified"], reverse=True)

        rowlimit = int(pageoffset) + int(rowlimit)

        results = {}

        results['total'] = len(jsondata)
        results['rowlimit'] = rowlimit
        results['results'] = jsondata[int(pageoffset):int(rowlimit)]
                
        return jsonify(results)   


@app.route('/api/v1/licence/<type>/<name>', methods = ['POST', 'GET'])
def get_license(type, name):
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['email_id']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        if request.args.get('offset'):
            pageoffset = request.args.get('offset')
            if request.args.get('limit'):
                rowlimit = request.args.get('limit')
            else:
                rowlimit = 50
        else:
            pageoffset = 0
            rowlimit = 50

        jsondata = {}

        if len(status_data) > 0:
            if status_data[0][0] == "active": 
                if os.path.exists("/var/DB/license/%s_license.json" % name):
                    with open("/var/DB/license/%s_license.json" % name, "r") as f:
                        jsondata = json.load(f)['results']
        
        data = []    
        
        rowlimit = int(pageoffset) + int(rowlimit)

        results = {}
        results['total'] = len(jsondata)
        results['rowlimit'] = rowlimit
        results['results'] = jsondata[int(pageoffset):int(rowlimit)]
                
        return jsonify(jsondata)


@app.route('/api/v1/active/ecosystem/<ecosystem>', methods = ['POST', 'GET'])
def get_echosystem(ecosystem):
    if request.method == 'POST':
        from datetime import datetime
        results = {}
        req_data = request.get_json()
        api_key = req_data['api-key']
        user_id = get_user_id(api_key)

        if not user_id:
            results['message'] = "API Key incorrect, Please contact support!!"
            results['error'] = True
            return results
        
        if not check_user_active(user_id):
            results['message'] = "User ID is not active, Please contact support!!"
            results['error'] = True
            return results

        type_s = "api"
        dst_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        api_type = "ACTIVE_ECOSYSTEM"
        filename = datetime.today().strftime("%Y-%m-%d_%H-%M")
        updateCounter(type_s, dst_ip, user_id, api_type, filename)

        now = datetime.now()
        results['publishedDate'] = now.strftime("%d_%m_%Y_%H_%M_%S")
            
        if request.args.get('offset'):
            pageoffset = request.args.get('offset')
            if request.args.get('limit'):
                rowlimit = request.args.get('limit')
            else:
                rowlimit = 50
        else:
            pageoffset = 0
            rowlimit = 50

        rowlimit = int(pageoffset) + int(rowlimit)

        filename = "%s.json" % ecosystem
        
        results['supported_ecosystem'] = []
        results['supported_type'] = []
        results['supported_type'].append("dependencies")
        results['supported_type'].append("platform")



        echosystems = ['c#', 'c', 'dart', 'elixir', 'go', 'java', 'javascript', 'php', 'python', 'ruby', 'rust']
        echosystem_platforms = ['ubuntu', 'debian', 'rhel', 'oracle_linux']

        if ecosystem not in echosystem_platforms and ecosystem not in echosystems:
            results['error'] = "ecosystem not supported"
            return jsonify(results)

        if ecosystem in echosystems:
            type = "dependencies"
        
        if ecosystem in echosystem_platforms:
            type = "platform"

        if type == "dependencies":
            for dep_file in os.listdir("/var/DB/feeds/language/"):
                results['supported_ecosystem'].append(dep_file)
                if filename == dep_file:
                    with open("/var/DB/feeds/language/%s" % filename, "r") as f:
                        jsondata1 = json.load(f)

                    jsondata1['results'].sort(key=lambda x: x["modified"], reverse=True)

                    jsondata1 = jsondata1['results']

                    with open("/var/DB/feeds/non-cve/noncve_feed.json", "r") as f:
                        jsondata2 = json.load(f)

                    jsondata2 = list(filter(lambda x:(ecosystem == x['language']),jsondata2['results']))

                    jsondata = jsondata1 + jsondata2
                    
                    results['total'] = len(jsondata)
                    results['rowlimit'] = rowlimit
                    results['data'] = jsondata[int(pageoffset):int(rowlimit)]
        
        if type == "platform":
            for dep_file in os.listdir("/var/DB/feeds/platform/"):
                results['supported_ecosystem'].append(dep_file)
                if ecosystem == dep_file:
                    if dep_file == "oracle_linux":
                        dep_file = "oracle"

                    platform_data = []
                    with open("/var/DB/feeds/platform/%s/%s.json" % (dep_file, dep_file), "r") as f:
                        jsondata = json.load(f)

                        for key, value in jsondata.items():

                            if isinstance(value, list):
                                platform_data.extend(value)
                                jsondata = platform_data
                    
                    jsondata.sort(key=lambda x: x["published"], reverse=True)

                    results['total'] = len(jsondata)
                    results['rowlimit'] = rowlimit
                    results['data'] = jsondata[int(pageoffset):int(rowlimit)]

        return jsonify(results)


@app.route('/api/v1/active/vulnerability/<cve>', methods = ['POST', 'GET'])
def get_vuln_cve(cve):
    if request.method == 'POST':
        from datetime import datetime
        results = {}
        req_data = request.get_json()

        api_key = req_data['api-key']
        user_id = get_user_id(api_key)
        if not user_id:
            results['message'] = "API Key incorrect, Please contact support!!"
            results['error'] = True
            return results
        
        if not check_user_active(user_id):
            results['message'] = "User ID is not active, Please contact support!!"
            results['error'] = True
            return results

        type_s = "api"
        dst_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        api_type = "ACTIVE_VULN_CVE"
        filename = datetime.today().strftime("%Y-%m-%d_%H-%M")
        updateCounter(type_s, dst_ip, user_id, api_type, filename)

        now = datetime.now()
        results['publishedDate'] = now.strftime("%d_%m_%Y_%H_%M_%S")

        jsondata1  = {}
        jsondata2 = {}
    
        if os.path.isfile("/var/DB/feed_update/feeds/cves/%s.json" % cve):
            with open("/var/DB/feed_update/feeds/cves/%s.json" % cve, "r") as f:
                jsondata1 = json.load(f)

            if os.path.isfile("/var/DB/feed_update/feeds/cves_map/%s.json" % cve):
                with open("/var/DB/feed_update/feeds/cves_map/%s.json" % cve, "r") as f:
                    jsondata2 = json.load(f)
        elif os.path.isfile("/var/DB/feeds/cves/%s.json" % cve):
            with open("/var/DB/feeds/cves/%s.json" % cve, "r") as f:
                jsondata1 = json.load(f)

            if os.path.isfile("/var/DB/feeds/cves_map/%s.json" % cve):
                with open("/var/DB/feeds/cves_map/%s.json" % cve, "r") as f:
                    jsondata2 = json.load(f)
        else:
            pass

        merged = {**jsondata1, **jsondata2}
        merged['publishedDate'] = now.strftime("%d_%m_%Y_%H_%M_%S")
        return jsonify(merged)


@app.route('/api/v1/active/year/<year>', methods = ['POST', 'GET'])
def get_year_wise(year):
    if request.method == 'POST':
        from datetime import datetime
        results = {}
        req_data = request.get_json()

        api_key = req_data['api-key']
        user_id = get_user_id(api_key)
        if not user_id:
            results['message'] = "API Key incorrect, Please contact support!!"
            results['error'] = True
            return results
        
        if not check_user_active(user_id):
            results['message'] = "User ID is not active, Please contact support!!"
            results['error'] = True
            return results

        type_s = "api"
        dst_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        api_type = "ACTIVE_YEAR"
        filename = datetime.today().strftime("%Y-%m-%d_%H-%M")
        updateCounter(type_s, dst_ip, user_id, api_type, filename)

        now = datetime.now()
        results['publishedDate'] = now.strftime("%d_%m_%Y_%H_%M_%S")
            
        if request.args.get('offset'):
            pageoffset = request.args.get('offset')
            if request.args.get('limit'):
                rowlimit = request.args.get('limit')
            else:
                rowlimit = 50
        else:
            pageoffset = 0
            rowlimit = 50

        rowlimit = int(pageoffset) + int(rowlimit)
        
        year_file = "%s_db.json" % year

        for dep_file in os.listdir("/var/DB/feeds/cvedb/"):
            if year_file == dep_file:
                with open("/var/DB/feeds/cvedb/%s" % year_file, "r") as f:
                    jsondata = json.load(f)

                results['total'] = len(jsondata)
                results['rowlimit'] = rowlimit
                results['data'] = jsondata[int(pageoffset):int(rowlimit)]
            
        return jsonify(results)

@app.route('/api/v1/active/ecosystem/<ecosystem>/<product>', methods = ['POST', 'GET'])
def get_package_echosystem(ecosystem, product):
    if request.method == 'POST':
        from datetime import datetime
        results = {}
        req_data = request.get_json()

        api_key = req_data['api-key']
        user_id = get_user_id(api_key)
        if not user_id:
            results['message'] = "API Key incorrect, Please contact support!!"
            results['error'] = True
            return results
        
        if not check_user_active(user_id):
            results['message'] = "User ID is not active, Please contact support!!"
            results['error'] = True
            return results

        type_s = "api"
        dst_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        api_type = "ACTIVE_ECOSYSTEM_PRODUCT"
        filename = datetime.today().strftime("%Y-%m-%d_%H-%M")
        updateCounter(type_s, dst_ip, user_id, api_type, filename)

        now = datetime.now()
        results['publishedDate'] = now.strftime("%d_%m_%Y_%H_%M_%S")
            
        if request.args.get('offset'):
            pageoffset = request.args.get('offset')
            if request.args.get('limit'):
                rowlimit = request.args.get('limit')
            else:
                rowlimit = 50
        else:
            pageoffset = 0
            rowlimit = 50

        rowlimit = int(pageoffset) + int(rowlimit)

        filename = "%s.json" % ecosystem

        if ecosystem == 'php':
            product = product.replace("-","/")
            # print(product)
        
        if ecosystem == 'java':
            product = product.replace("_",":")
            # print(product)

        if ecosystem == 'go':
            product = product.replace("-","/")
        
        results['supported_ecosystem'] = []
        results['supported_type'] = []
        results['supported_type'].append("dependencies")
        results['supported_type'].append("platform")
        
        if ecosystem in os.listdir("/var/DB/feeds/language/"):
            for dep_file in os.listdir("/var/DB/feeds/language/"):
                results['supported_ecosystem'].append(dep_file)
                if filename == dep_file:
                    with open("/var/DB/feeds/language/%s" % filename, "r") as f:
                        jsondata1 = json.load(f)

                    jsondata1['results'].sort(key=lambda x: x["modified"], reverse=True)

                    jsondata1 = list(filter(lambda x: (product == x['package']), jsondata1["results"]))
                    # print("1111111111111", jsondata1)

                    with open("/var/DB/feeds/non-cve/noncve_feed.json", "r") as f:
                        jsondata2 = json.load(f)

                    jsondata2 = list(filter(lambda x:(product == x['product']),jsondata2['results']))
                    # print("222222222222", jsondata2)

                    jsondata = jsondata1 + jsondata2

                    results['total'] = len(jsondata)
                    results['rowlimit'] = rowlimit
                    results['data'] = jsondata[int(pageoffset):int(rowlimit)]
        
        if ecosystem in os.listdir("/var/DB/feeds/platform/"):
            for dep_file in os.listdir("/var/DB/feeds/platform/"):
                results['supported_ecosystem'].append(dep_file)
                if ecosystem == dep_file:
                    if dep_file == "oracle_linux":
                        dep_file = "oracle"

                    platform_data = []
                    with open("/var/DB/feeds/platform/%s/%s.json" % (dep_file, dep_file), "r") as f:
                        jsondata = json.load(f)

                        for key, value in jsondata.items():

                            if isinstance(value, list):
                                platform_data.extend(value)
                                jsondata = platform_data

                    jsondata = list(filter(lambda x: (product == x['package']), jsondata))
                    
                    jsondata.sort(key=lambda x: x["published"], reverse=True)

                    results['total'] = len(jsondata)
                    results['rowlimit'] = rowlimit
                    results['data'] = jsondata[int(pageoffset):int(rowlimit)]


        return jsonify(results)


@app.route('/api/v1/passive/ecosystem/<ecosystem>/<packages>', methods = ['POST', 'GET'])
def get_passive_package_echosystem(ecosystem, packages):
    if request.method == 'POST':
        from datetime import datetime
        results = {}
        req_data = request.get_json()

        api_key = req_data['api-key']
        user_id = get_user_id(api_key)
        if not user_id:
            results['message'] = "API Key incorrect, Please contact support!!"
            results['error'] = True
            return results
        
        if not check_user_active(user_id):
            results['message'] = "User ID is not active, Please contact support!!"
            results['error'] = True
            return results

        type_s = "api"
        dst_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        api_type = "PASSIVE_ECOSYSTEM_PACKAGE"
        filename = datetime.today().strftime("%Y-%m-%d_%H-%M-%S") + '.json'
        updateCounter(type_s, dst_ip, user_id, api_type, filename)

        res = send_task("tasks.get_packages_feeds", [user_id, packages, ecosystem, filename])
        result_id = res.id

        results['taskid'] = result_id
        return jsonify(results)

@app.route('/api/v1/passive/year/<years>', methods = ['POST', 'GET'])
def get_passive_year_wise(years):
    if request.method == 'POST':
        from datetime import datetime
        results = {}
        req_data = request.get_json()

        api_key = req_data['api-key']
        user_id = get_user_id(api_key)
        if not user_id:
            results['message'] = "API Key incorrect, Please contact support!!"
            results['error'] = True
            return results
        
        if not check_user_active(user_id):
            results['message'] = "User ID is not active, Please contact support!!"
            results['error'] = True
            return results

        type_s = "api"
        dst_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        api_type = "PASSIVE_YEAR"
        filename = datetime.today().strftime("%Y-%m-%d_%H-%M-%S") + '.json'
        updateCounter(type_s, dst_ip, user_id, api_type, filename)
            
        res = send_task("tasks.get_year_feeds", [user_id, years, filename])
        result_id = res.id

        results['taskid'] = result_id
        
        return jsonify(results)
    
@app.route('/api/v1/passive/vulnerability/<cves>', methods = ['POST', 'GET'])
def get_passive_vuln_cve(cves):
    if request.method == 'POST':
        from datetime import datetime
        results = {}
        req_data = request.get_json()

        api_key = req_data['api-key']
        user_id = get_user_id(api_key)
        if not user_id:
            results['message'] = "API Key incorrect, Please contact support!!"
            results['error'] = True
            return results
        
        if not check_user_active(user_id):
            results['message'] = "User ID is not active, Please contact support!!"
            results['error'] = True
            return results

        type_s = "api"
        dst_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        api_type = "PASSIVE_VULN_CVES"
        filename = datetime.today().strftime("%Y-%m-%d_%H-%M-%S") + '.json'
        updateCounter(type_s, dst_ip, user_id, api_type, filename)

        res = send_task("tasks.get_cves_feeds", [user_id, cves, filename])
        result_id = res.id

        results['taskid'] = result_id
        
        return jsonify(results)
    
@app.route('/api/v1/passive/ecosystem/<ecosystem>', methods = ['POST', 'GET'])
def get_passive_echosystem(ecosystem):
    if request.method == 'POST':
        from datetime import datetime
        results = {}
        req_data = request.get_json()

        api_key = req_data['api-key']
        user_id = get_user_id(api_key)
        if not user_id:
            results['message'] = "API Key incorrect, Please contact support!!"
            results['error'] = True
            return results
        
        if not check_user_active(user_id):
            results['message'] = "User ID is not active, Please contact support!!"
            results['error'] = True
            return results

        type_s = "api"
        dst_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        api_type = "PASSIVE_ECOSYSTEM"
        filename = datetime.today().strftime("%Y-%m-%d_%H-%M-%S") + '.json'
        updateCounter(type_s, dst_ip, user_id, api_type, filename)

        res = send_task("tasks.get_echosystem_feeds", [user_id, ecosystem, filename])
        print(res)
        result_id = res.id

        results['taskid'] = result_id

        return jsonify(results)     
    
@app.route('/api/v1/ecosystem', methods = ['GET'])
def get_echosystem_lists():
    if request.method == 'GET':
        results = {}
        
        dep_ecosystems = [{"language":"python","image":"python.png"},{"language":"c","image":"c.png"},{"language":"cpp","image":"cpp.png"},{"language":"go","image":"go.png"},{"language":"java","image":"java.png"},{"language":"javascript","image":"javascript.png"},{"language":"php","image":"php.png"},{"language":"ruby","image":"ruby.png"},{"language":"rust","image":"rust.png"},{"language":"dart","image":"dart.png"},{"language":"elixir","image":"elixir.png"}]
        plat_ecosystem = [{"language":"ubuntu","image":"ubuntu.png"},{"language":"debian","image":"debian.png"},{"language":"rhel","image":"rhel.png"},{"language":"oracle_linux","image":"oracle_linux.png"}]
        
        results['dependencies'] = dep_ecosystems
        results['platform'] = plat_ecosystem

        return jsonify(results)

@app.route('/api/v1/license/ecosystem', methods = ['GET'])
def get_license_echosystem_lists():
    if request.method == 'GET':
        results = {}
        
        # dep_ecosystems = [{"language":"python","image":"python.png"},{"language":"java","image":"java.png"},{"language":"javascript","image":"javascript.png"},{"language":"php","image":"php.png"}],{"language":"suse linux","image":"suse_linux.png"}
        dep_ecosystems = [{"language":"python","image":"python.png"},{"language":"c#","image":"c.png"},{"language":"java","image":"java.png"},{"language":"javascript","image":"javascript.png"},{"language":"php","image":"php.png"},{"language":"ruby","image":"ruby.png"},{"language":"rust","image":"rust.png"},{"language":"dart","image":"dart.png"},{"language":"elixir","image":"elixir.png"}]
        plat_ecosystem = [{"language":"ubuntu","image":"ubuntu.png"},{"language":"debian","image":"debian.png"}]
        
        results['dependencies'] = dep_ecosystems
        results['platform'] = plat_ecosystem

        return jsonify(results)

@app.route('/api/v1/ecosystem/<ecosystem>', methods = ['GET'])
def get_default_echosystem(ecosystem):
    if request.method == 'GET':
        results = {}
        results['columns'] = []

        resCol = {}
        resCol['title'] = "Package"
        resCol['field'] = "package"
        results['columns'].append(resCol)

        rescol = {}
        rescol['title'] = "NiahID"
        rescol['field'] = "niah_id"
        results['columns'].append(rescol)

        resCol = {}
        resCol['title'] = "Severity"
        resCol['field'] = "severity"
        results['columns'].append(resCol)

        resCol = {}
        resCol['title'] = "Published"
        resCol['field'] = "published"
        results['columns'].append(resCol)

        if request.args.get('offset'):
            pageoffset = request.args.get('offset')
            if request.args.get('limit'):
                rowlimit = request.args.get('limit')
            else:
                rowlimit = 50
        else:
            pageoffset = 0
            rowlimit = 50

        rowlimit = int(pageoffset) + int(rowlimit)

        filename = "%s.json" % ecosystem
        
        ecosystems = ['c#', 'c', 'dart', 'elixir', 'go', 'java', 'javascript', 'php', 'python', 'ruby', 'rust']
        ecosystem_platforms = ['ubuntu', 'debian', 'rhel', 'oracle_linux']
        unknown_vulns = ['noncve']
        
        if ecosystem not in ecosystem_platforms and ecosystem not in ecosystems and ecosystem not in unknown_vulns:
            results['error'] = "ecosystem not supported"
            return jsonify(results)

        if ecosystem in ecosystems:
            eco_type = "dependencies"
        
        if ecosystem in ecosystem_platforms:
            eco_type = "platform"

        if ecosystem in unknown_vulns:
            eco_type = "noncve"

        if eco_type == "dependencies": 
            resCol = {}
            resCol['title'] = "Modified"
            resCol['field'] = "modified"
            results['columns'].append(resCol)

        if eco_type == "dependencies":
            for dep_file in os.listdir("/var/DB/feeds/language/"):
                if filename == dep_file:
                    with open("/var/DB/feeds/language/%s" % filename, "r") as f:
                        jsondata1 = json.load(f)
                    
                    jsondata1['results'].sort(key=lambda x: x["modified"], reverse=True)
                    jsondata1 = jsondata1['results']

                    with open("/var/DB/feeds/non-cve/noncve_feed.json", "r") as f:
                        jsondata2 = json.load(f)

                    jsondata2 = list(filter(lambda x:(ecosystem == x['language']),jsondata2['results']))

                    jsondata = jsondata1 + jsondata2
                    
                    results['total'] = len(jsondata)
                    results['rowlimit'] = rowlimit
                    results['data'] = jsondata[int(pageoffset):int(rowlimit)]
      
        if eco_type == "platform":
            for dep_file in os.listdir("/var/DB/feeds/platform/"):
                if ecosystem == dep_file:
                    if dep_file == "oracle_linux":
                        dep_file = "oracle"

                    platform_data = []
                    with open("/var/DB/feeds/platform/%s/%s.json" % (dep_file, dep_file), "r") as f:
                        jsondata = json.load(f)

                        for key, value in jsondata.items():

                            if isinstance(value, list):
                                platform_data.extend(value)
                                jsondata = platform_data
                    
                    jsondata.sort(key=lambda x: x["published"], reverse=True)

                    results['total'] = len(jsondata)
                    results['rowlimit'] = rowlimit
                    print(results)
                    results['data'] = jsondata[int(pageoffset):int(rowlimit)]

        if eco_type == "noncve":
            with open("/var/DB/feeds/non-cve/noncve_feed.json", "r") as f:
                jsondata = json.load(f)

            results['total'] = len(jsondata["results"])
            results['rowlimit'] = rowlimit
            results['data'] = jsondata["results"][pageoffset:rowlimit]
        
        print(results)
        return jsonify(results)


def get_dep(ecosystem, product):
    depe_file = "/var/DB/feeds/deps/%s_dep.json" % ecosystem
    if os.path.isfile(depe_file):
        with open (depe_file, "r") as f:
            jsondata = json.load(f)
            try:
                results = jsondata[product]
            except:
                results = []

        return results
    else:
        print("Dependency File not found..")


def get_rev_dep(ecosystem, product):
    rev_file = "/var/DB/feeds/deps/%s_rev.json" % ecosystem
    if os.path.isfile(rev_file):
        with open ("/var/DB/feeds/deps/%s_rev.json" % ecosystem, "r") as f:
            jsondata = json.load(f)
            try:
                results = jsondata[product]
            except:
                results = []

        return results
    else:
        print("Reverse dependency File not found..")


def get_dep_tree(ecosystem, product):
    depe_file = "/var/DB/feeds/deps/%s_dep.json" % ecosystem
    if os.path.isfile(depe_file):
        with open ("/var/DB/feeds/deps/%s_dep.json" % ecosystem, "r") as f:
            jsondata = json.load(f)

            results = {}
            results[product] = {}
            try:
                for p1 in jsondata[product]:
                    results[product][p1] = {}

                    if p1 in jsondata:
                        if len(jsondata[p1]) > 0:
                            for p2 in jsondata[p1]:
                                results[product][p1][p2] = {}

                                if p2 in jsondata:
                                    if len(jsondata[p2]) > 0:
                                        for p3 in jsondata[p2]:
                                            results[product][p1][p2][p3] = {}

                                            if p3 in jsondata:
                                                if len(jsondata[p3]) > 0:
                                                    for p4 in jsondata[p3]:
                                                        results[product][p1][p2][p3][p4] = {}
                                                        
                                                        if p4 in jsondata:
                                                            if len(jsondata[p4]) > 0:
                                                                for p5 in jsondata[p4]:
                                                                    results[product][p1][p2][p3][p4][p5] = {}
            except:
                results = {}
            
            return results
    else:
        print("Dependency File not found..")




@app.route('/api/v1/ecosystem/<ecosystem>/<product>', methods = ['GET'])
def get_default_package_echosystem(ecosystem, product):
    if request.method == 'GET':
        ecosystems = ['c#', 'c', 'dart', 'elixir', 'go', 'java', 'javascript', 'php', 'python', 'ruby', 'rust']
        ecosystem_platforms = ['ubuntu', 'debian', 'rhel', 'oracle_linux']

        if ecosystem not in ecosystem_platforms and ecosystem not in ecosystems:
            results['error'] = "ecosystem not supported"
            return jsonify(results)

        if ecosystem in ecosystems:
            eco_type = "dependencies"
        
        if ecosystem in ecosystem_platforms:
            eco_type = "platform"

        print("11111111111",product)

        if '____' in str(product):
            product = product.replace("____", "/")

        if '@@@@@' in str(product):
            product = product.replace("@@@@@", ":")

        if 'p@lu_s' in str(product):
            product = product.replace("p@lu_s", "+")

        print("22222222222",product)

        results = {}
    
        results['columns'] = []

        rescol = {}
        rescol['title'] = "NiahID"
        rescol['field'] = "niah_id"
        results['columns'].append(rescol)

        resCol = {}
        resCol['title'] = "Severity"
        resCol['field'] = "severity"
        results['columns'].append(resCol)

        if eco_type == "platform":
            resCol = {}
            resCol['title'] = "OSNAME"
            resCol['field'] = "osname"
            results['columns'].append(resCol)
        else:
            resCol = {}
            resCol['title'] = "Installer"
            resCol['field'] = "installer"
            results['columns'].append(resCol)

        resCol = {}
        resCol['title'] = "Versions"
        resCol['field'] = "versions"
        results['columns'].append(resCol)

        resCol = {}
        resCol['title'] = "Published"
        resCol['field'] = "published"
        results['columns'].append(resCol)

        if eco_type == "dependencies":
            resCol = {}
            resCol['title'] = "Modified"
            resCol['field'] = "modified"
            results['columns'].append(resCol)

        if request.args.get('severity'):
            severity = request.args.get('severity')
        if request.args.get('access_vector'):
            access_vector = request.args.get('access_vector')

        if request.args.get('offset'):
            pageoffset = request.args.get('offset')
            if request.args.get('limit'):
                rowlimit = request.args.get('limit')
            else:
                rowlimit = 50
        else:
            pageoffset = 0
            rowlimit = 50

        rowlimit = int(pageoffset) + int(rowlimit)

        filename = "%s.json" % ecosystem

        if eco_type == "dependencies":
            for dep_file in os.listdir("/var/DB/feeds/language/"):
                if filename == dep_file:
                    with open("/var/DB/feeds/language/%s" % filename, "r") as f:
                        jsondata1 = json.load(f)

                    jsondata1['results'].sort(key=lambda x: x["modified"], reverse=True)

                    jsondata1 = list(filter(lambda x: (product == x['package']), jsondata1["results"]))

                    osname = ''

                    # if severity:
                    #     jsondata1 = list(filter(lambda x: (severity == x['severity']), jsondata1))
                    
                    # if access_vector:
                    #     jsondata1 = list(filter(lambda x: (access_vector == x['access_vector']), jsondata1))

                    dependency = get_dep(ecosystem, product)
                    reversed_dep = get_rev_dep(ecosystem, product)
                    dep_tree = get_dep_tree(ecosystem, product)


                    with open("/var/DB/feeds/non-cve/noncve_feed.json", "r") as f:
                        jsondata2 = json.load(f)
                    try:
                        jsondata2 = list(filter(lambda x:(product == x['product']),jsondata2['results']))
                    except:
                        jsondata2 = []
                        
                    jsondata = jsondata1 + jsondata2
                    osname = ''

                    results['total'] = len(jsondata)
                    results['rowlimit'] = rowlimit
                    results['data'] = jsondata[int(pageoffset):int(rowlimit)]
                    results['dependency'] = dependency
                    results['reversed_dep'] = reversed_dep
                    results['dep_tree'] = dep_tree

        if eco_type == "platform":
            for dep_file in os.listdir("/var/DB/feeds/platform/"):
                if ecosystem == dep_file:
                    if dep_file == "oracle_linux":
                        dep_file = "oracle"

                    platform_data = []
                    with open("/var/DB/feeds/platform/%s/%s.json" % (dep_file, dep_file), "r") as f:
                        jsondata = json.load(f)

                        
                        for key, value in jsondata.items():

                            if isinstance(value, list):
                                platform_data.extend(value)
                                jsondata = platform_data

                    jsondata.sort(key=lambda x: x["published"], reverse=True)

                    jsondata = list(filter(lambda x: (product == x['package']), jsondata))
                    # print(jsondata)
                    osname = jsondata[0]['osname']
                    print('------', osname)
                    
                    dependency = get_dep(ecosystem, product)
                    reversed_dep = get_rev_dep(ecosystem, product)
                    dep_tree = get_dep_tree(ecosystem, product)

                    # if severity:
                    #     jsondata = list(filter(lambda x: (severity == x['severity']), jsondata))
                    
                    # if access_vector:
                    #     jsondata = list(filter(lambda x: (access_vector == x['access_vector']), jsondata))

                    results['total'] = len(jsondata)
                    results['rowlimit'] = rowlimit
                    results['data'] = jsondata[int(pageoffset):int(rowlimit)]
                    results['dependency'] = dependency
                    results['reversed_dep'] = reversed_dep
                    results['dep_tree'] = dep_tree

        res = get_json_feeds()
        check = True
        info = res.get_package_details(osname, product, ecosystem, check)


        if info:
            results['info'] = info
        else:
            results['info'] = {}

        results['info']['product'] = product
        results['info']['ecosystem'] = ecosystem

        if len(results['data']) > 0:
            if 'purl' in results['data'][0]:
                results['info']['purl'] = results['data'][0]['purl']
            else:
                results['info']['purl'] = ''
        else:
            results['info']['purl'] = ''

        # print(results)
        
        return jsonify(results)

@app.route('/api/v1/vulnerability/front/<niahid>', methods = ['GET'])
def get_default_front_vuln_cve(niahid):
    if request.method == 'GET':

        if '____' in str(niahid):
            niahid = niahid.replace("____", "/")
        
        ecosystem = request.args.get('ecosystem')

        ecosystems = ['c#', 'c', 'dart', 'elixir', 'go', 'java', 'javascript', 'php', 'python', 'ruby', 'rust']
        ecosystem_platforms = ['ubuntu', 'debian', 'rhel', 'oracle_linux']

        if ecosystem not in ecosystem_platforms and ecosystem not in ecosystems:
            results = {}
            results['error'] = "ecosystem not supported"
            return jsonify(results)

        if ecosystem in ecosystems:
            eco_type = "dependencies"
        
        if ecosystem in ecosystem_platforms:
            eco_type = "platform"
        
        filename = "%s.json" % ecosystem
        
        if eco_type == "dependencies":
            for dep_file in os.listdir("/var/DB/feeds/language/"):
                if filename == dep_file:
                    with open("/var/DB/feeds/language/%s" % filename, "r") as f:
                        jsondata = json.load(f)
                    
                    jsondata['results'].sort(key=lambda x: x["modified"], reverse=True)

                    jsondata = list(filter(lambda x: (niahid == x['niah_id']), jsondata["results"]))

        if eco_type == "platform":
            for dep_file in os.listdir("/var/DB/feeds/platform/"):
                if ecosystem == dep_file:
                    if dep_file == "oracle_linux":
                        dep_file = "oracle"

                    platform_data = []
                    with open("/var/DB/feeds/platform/%s/%s.json" % (dep_file, dep_file), "r") as f:
                        jsondata = json.load(f)
                        for key, value in jsondata.items():

                            if isinstance(value, list):
                                platform_data.extend(value)
                                jsondata = platform_data
    

                    jsondata = list(filter(lambda x: (niahid == x['niah_id']), jsondata))
                    jsondata.sort(key=lambda x: x["published"], reverse=True)

        for data in jsondata:
            cves = data['cves']
            if len(cves) > 0:
                res = {}
                res['vulns'] = cves
                res['ecosystem'] = ecosystem
                return jsonify(res)
            else:
                res = {}
                res['vulns'] = []
                res['vulns'].append(niahid)
                res['ecosystem'] = ecosystem
                return jsonify(res)

@app.route('/api/v1/vulnerability/<niahid>', methods = ['GET'])
def get_default_vuln_cve(niahid):
    if request.method == 'GET':
        jsondata = {}
        try:
            if 'CVE-' in niahid or 'cve-' in niahid:
                jsondata1 = {}
                jsondata2 = {}
                if os.path.isfile("/var/DB/feeds/cves/%s.json" % niahid.upper()):
                    with open("/var/DB/feeds/cves/%s.json" % niahid.upper(), "r") as f:
                        jsondata1 = json.load(f)

                    if os.path.isfile("/var/DB/feeds/cve_map/%s.json" % niahid.upper()):
                        with open("/var/DB/feeds/cve_map/%s.json" % niahid.upper(), "r") as f:
                            jsondata2 = json.load(f)

                    merged = {**jsondata1, **jsondata2}

                    return jsonify(merged)
                else:
                    res = {}
                    return jsonify(jsondata)
            else:
                if os.path.isfile("/var/DB/feeds/non-cve/%s.json" % niahid):
                    with open("/var/DB/feeds/non-cve/%s.json" % niahid, "r") as f:
                        jsondata = json.load(f)

                    return jsonify(jsondata)
                else:
                    res = {}
                    return jsonify(jsondata)
        except:
            res = {}
            return jsonify(jsondata)


@app.route('/api/v1/vulnerability/update', methods = ['GET'])
def get_default_vuln_cve_update():
    if request.method == 'GET':
        results = {}
        results['daywise'] = []
        results['weekwise'] = []
        results['monthwise'] = []

        with open("/var/DB/feeds/updates/1_day.json", "r") as f:
            jsondata = json.load(f)
            
        for data in jsondata:
            print(data)
            print(len(data))
            type = data['type']
            type_name = data['type_name']
            if 'cves' in data:
                cve_id = data['cves']
            else:
                cve_id = []

            if 'niah_id' in data:
                niahid = data['niah_id']
            else:
                niahid = ''

            if 'published' in data:
                published_date = data['published']
            else:
                published_date = ''

            if 'description' in data:
                details = data['description']
            elif 'summary' in data:
                details = data['summary']
            else:
                details = ''
            res = {}
            res['type_name'] = type_name
            res['cve_id'] = cve_id
            res['niahid'] = niahid
            res['published_date'] = published_date
            res['details'] = details

            if res['type_name'] != '' and res['cve_id'] != '' and res['niahid'] != '' and res['published_date'] != '' and res['details']:
                results['daywise'].append(res)
            else:
                pass

        with open("/var/DB/feeds/updates/7_day.json", "r") as f:
            jsondata = json.load(f)

        for data in jsondata:
            type = data['type']
            type_name = data['type_name']
            if 'cves' in data:
                cve_id = data['cves']
            else:
                cve_id = []

            if 'niah_id' in data:
                niahid = data['niah_id']
            else:
                niahid = ''
                
            if 'published' in data:
                published_date = data['published']
            else:
                published_date = ''

            if 'description' in data:
                details = data['description']
            elif 'summary' in data:
                details = data['summary']
            else:
                details = ''
            
            res = {}
            res['type_name'] = type_name
            res['cve_id'] = cve_id
            res['niahid'] = niahid
            res['published_date'] = published_date
            res['details'] = details

            if res['type_name'] != '' and res['cve_id'] != '' and res['niahid'] != '' and res['published_date'] != '' and res['details']:
                results['weekwise'].append(res)
            else:
                pass


        with open("/var/DB/feeds/updates/30_day.json", "r") as f:
            jsondata = json.load(f)

        for data in jsondata:
            type = data['type']
            type_name = data['type_name']
            if 'cves' in data:
                cve_id = data['cves']
            else:
                cve_id = []

            if 'niah_id' in data:
                niahid = data['niah_id']
            else:
                niahid = ''
                
            if 'published' in data:
                published_date = data['published']
            else:
                published_date = ''

            if 'description' in data:
                details = data['description']
            elif 'summary' in data:
                details = data['summary']
            else:
                details = ''
            
            res = {}
            res['type_name'] = type_name
            res['cve_id'] = cve_id
            res['niahid'] = niahid
            res['published_date'] = published_date
            res['details'] = details

            if res['type_name'] != '' and res['cve_id'] != '' and res['niahid'] != '' and res['published_date'] != '' and res['details']:
                results['monthwise'].append(res)
            else:
                pass


        return jsonify(results)

@app.route('/api/v1/get/profile', methods = ['GET'])
def get_profile():
    if request.method == 'GET':
        user_id = request.args.get('user_id')

        query = "select firstname, lastname, companyname, address, city, state, pincode, country, emailid, phone, code, status, subscription, users, scans, api_key from license_master_db where user_id='%s'" % user_id
        g.cursor.execute(query)
        profileDB = g.cursor.fetchall();

        results = {}
        for pDB in profileDB:
            results['firstname'] = pDB[0]
            results['lastname'] = pDB[1]
            results['companyname'] = pDB[2]
            results['address'] = pDB[3]
            results['city'] = pDB[4]
            results['state'] = pDB[5]
            results['pincode'] = pDB[6]
            results['country'] = pDB[7]
            results['emailid'] = pDB[8]
            results['phone'] = pDB[9]
            results['code'] = pDB[10]
            results['status'] = pDB[11]
            results['subscription'] = pDB[12]
            results['users'] = pDB[13]
            results['scans'] = pDB[14]
            results['api_key'] = pDB[15]
        
        return jsonify(results)


@app.route('/api/subscription/update', methods = ['POST', 'GET'])
def updateSubscription():
    if request.method == 'POST':
        print('1111111111111111')
        req_data = request.get_json()
        print("===========", req_data)

        firstname = req_data['firstname']
        lastname = req_data['lastname']
        companyname = req_data['companyname']
        city = req_data['city']
        state = req_data['state']
        pincode = req_data['pincode']
        phone = req_data['phone']
        country = req_data['country']
        emailid = req_data['emailid']
        address = req_data['address']
        users = req_data['users']
        scans = req_data['scans']
        code = req_data['code']
        user_id = req_data['user_id']
        subscription = req_data['subscription']
        status = req_data['status']
 
        query = "update license_master_db set firstname='%s', lastname='%s', companyname='%s', city='%s', state='%s', pincode='%s', phone='%s', country='%s', emailid='%s', address='%s', users='%s', scans='%s', code='%s', subscription='%s', status='%s' where user_id='%s'" % (firstname, lastname, companyname, city, state, pincode, phone, country, emailid, address, users, scans, code, subscription, status, user_id)

        print(query)
        g.cursor.execute(query)
        g.conn.commit()

        res = {}
        res['message'] = "Updated successfully!!"
        return jsonify(res)


@app.route('/api/subscription/update/status', methods = ['POST', 'GET'])
def updateStatusSubscription():
    if request.method == 'POST':
        req_data = request.get_json()
        user_id = req_data['user_id']
        status = req_data['status']
 
        query = "update license_master_db set status='%s' where user_id='%s'" % (status, user_id)
        print(query)
        g.cursor.execute(query)
        g.conn.commit()

        res = {}
        res['message'] = "Updated successfully!!"
        return jsonify(res)

@app.route('/api/v1/subscription/details', methods = ['GET'])
def subscriptionDetails():
    if request.method == 'GET':
        with open('sub_details.json') as f:
            results = json.load(f)
        return jsonify(results)

@app.route('/api/v1/dashboard/details', methods = ['POST','GET'])
def dashboardDetails():
    if request.method == 'GET':

        # req_data = request.get_json()
        # user_id = req_data['user_id']
        
        user_id = request.args.get('user_id')
        print(user_id)

        results = {}
        results['service_usage'] = []

        results['vulnerability_intelligence'] = {}
        results['vulnerability_intelligence']['graph'] = []
        results['vulnerability_intelligence']['statistics'] = {}


        query = "select SUM(CAST(credit AS numeric)) from counter_tab where user_id='%s'" % user_id
        print(query)
        g.cursor.execute(query)
        credit_usage = g.cursor.fetchone()[0]
        results['service_usage'].append({'credit_usage':credit_usage})


        query = "select COUNT(api_type) from counter_tab where user_id='%s'" % user_id
        print(query)
        g.cursor.execute(query)
        total_api_call = g.cursor.fetchone()[0]
        results['service_usage'].append({'total_api_call':total_api_call})


        query = "select COUNT(*) from counter_tab where api_type LIKE 'ACTIVE%%' AND user_id='%s'" % user_id
        print(query)
        g.cursor.execute(query)
        active_api_call = g.cursor.fetchone()[0]
        results['service_usage'].append({'active_api_call':active_api_call})


        query = "select COUNT(*) from counter_tab where api_type LIKE 'PASSIVE%%' AND user_id='%s'" % user_id
        print(query)
        g.cursor.execute(query)
        passive_api_call = g.cursor.fetchone()[0]
        results['service_usage'].append({'passive_api_call':passive_api_call})

        with open('/var/DB/feeds/updates/day_wise_update.json',"r") as f:
            graphData = json.load(f)

        for data in graphData:
            graph_dict = {}
            graph_dict['x_axis'] = data['date']
            graph_dict['y_axis'] = data['total']
            results['vulnerability_intelligence']['graph'].append(graph_dict)

        with open('/var/DB/feeds/updates/counts.json',"r") as f:
            statData = json.load(f)

        print(statData)

        results['vulnerability_intelligence']['statistics']['day'] = statData['1_day']
        results['vulnerability_intelligence']['statistics']['week'] = statData['1_week']
        results['vulnerability_intelligence']['statistics']['month'] = statData['1_month']
        results['vulnerability_intelligence']['statistics']['total'] = statData['total']
        results['vulnerability_intelligence']['statistics']['year'] = {}
        print(results)

        return jsonify(results)


@app.route('/api/v1/subscribe', methods = ['GET'])
def subscription_api():
    if request.method == 'GET':
        user_id = request.args.get('user_id')

        res = {}

        sub_type = ''

        if 'product' in request.args:
            product = request.args.get('product')
            ecosystem = request.args.get('ecosystem')
            print(ecosystem)
            print(product)
            sub_type = 'product'
            res['product'] = product
            res['ecosystem'] = ecosystem


        if 'niah_id' in request.args:
            niah_id = request.args.get('niah_id')
            sub_type = 'niah_id'
            res['niah_id'] = niah_id

        query = "insert into subscribe_tab(user_id, sub_type, data) values('%s', '%s', '%s')" % (user_id, sub_type, json.dumps(res))
        g.cursor.execute(query)
        g.conn.commit()

        return jsonify(res)


@app.route('/api/v1/subscribe/list', methods = ['GET'])
def subscription_api_list():
    if request.method == 'GET':
        user_id = request.args.get('user_id')
        # print(req_data)
        # user_id = req_data['user_id']

        # print(user_id)

        query = "select id, sub_type, data from subscribe_tab where user_id='%s'" % user_id

        g.cursor.execute(query)
        alert_list = g.cursor.fetchall();

        results = []
        for alert in alert_list:
            alert_dict = {}
            alert_dict['id'] = alert[0]
            alert_dict['sub_type'] = alert[1]
            alert_dict['data'] = alert[2]
            results.append(alert_dict)
        
        return jsonify(results)
    


@app.route('/api/v1/subscribe/delete', methods=['DELETE'])
def delete_subscription():
    if request.method == 'DELETE':
        id = request.args.get('id')
        user_id = request.args.get('user_id')
        # print(id, "==========", user_id)
        # data = request.args.get('data')

        query = "DELETE FROM subscribe_tab WHERE id='%s' AND user_id='%s'" % (id, user_id)
        print(query)

        g.cursor.execute(query)
        g.conn.commit()

        return jsonify({"message": "Allert Removed Successfully..!!"})

@app.route('/api/v1/passive/reportlist', methods = ['POST','GET'])
def passive_report_list():
    if request.method == 'POST':
        req_data = request.get_json()
        user_id = req_data['user_id']
        print(user_id)
        # user_id = request.args.get('user_id')

        query = "select * from counter_tab where user_id = '%s'" % user_id

        g.cursor.execute(query)
        report_list = g.cursor.fetchall();

        print(report_list)

        results = []
        for report in report_list:
            report_dict = {}
            report_dict['id'] = report[0]
            report_dict['type'] = report[1]
            report_dict['user_id'] = report[2]
            report_dict['api_type'] = report[3]
            report_dict['date1'] = report[4]
            report_dict['reportname'] = report[7]
            results.append(report_dict)
        
        return jsonify(results)
    
@app.route('/api/v1/passive/reportfetch/<reportname>', methods = ['POST','GET'])
def passive_report_fetch(reportname):
    if request.method == 'POST':
        req_data = request.get_json()
        # print("1111",req_data)
        user_id = req_data['user_id']
        # user_id = request.args.get('user_id')
        print(user_id)

        path = 'static/report/%s/passive/' % user_id
        file_path = os.path.join(path, reportname)
        print(file_path)

        if os.path.isfile(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            return "File not found..!!"
    else:
        return "Invalid Request Method.."
    

def get_niah_id_data(niah_id):
    with open('/var/DB/feeds/updates/1_day.json', 'r') as update:
        dailyData = json.load(update)
        for data in dailyData:
            if data.get("niah_id") == niah_id:
                return data
            
    return None
        


def get_eco_prod_data(ecosystem_product):
    ecosystem, product = ecosystem_product.split('/')
    with open('/var/DB/feeds/updates/1_day.json', 'r') as update:
        dailyData = json.load(update)
        for data in dailyData:
            if data.get("type") == "language":
                ecosystem = data.get("language")
            if data.get("type") == "platform":
                ecosystem = data.get("type_name")
            package = data.get("package")
            if ecosystem == ecosystem and package == product:
                return data
            
    return None
        
            

@app.route('/api/v1/daily_email_update', methods = ['POST','GET'])
def generate_update_report():
    query  = "select user_id from license_master_db"
    g.cursor.execute(query)

    user_list = [row[0] for row in g.cursor.fetchall()]

    print(user_list)

    update_report = []

    for user_id in user_list:
        print(user_id)

        query = "select emailid from license_master_db where user_id='%s'" % user_id
        g.cursor.execute(query)
        recipient = g.cursor.fetchone()[0]
        print(recipient)

        query = "select data from subscribe_tab where user_id='%s'" % user_id
        g.cursor.execute(query)
        userData = g.cursor.fetchall();
        niah_id_list = []
        product_list = []

        for uData in userData:
            data = uData[0]
            if 'niah_id' in data:
                niah_id_list.append(data['niah_id'])
            if 'product' in data and 'ecosystem' in data:
                product_list.append(f"{data['ecosystem']}/{data['product']}")


        niah_id_list = list(set(niah_id_list))
        product_list = list(set(product_list))

        print("111111",niah_id_list)
        print("111111",product_list)


        niah_id_update = []
        product_update = []

        

        with open('/var/DB/feeds/updates/1_day.json', 'r') as update:
            dailyData = json.load(update)
            niah_id_data = []
            eco_prod_data = []
            for data in dailyData:
                niah_id = data.get("niah_id")
                if niah_id in niah_id_list:
                    niah_id_update.append(niah_id)
                
                
            for data in dailyData:

                if data.get("type") == "language":
                    language = data.get("language")
                if data.get("type") == "platform":
                    language = data.get("type_name")
                package = data.get("package")

                if language and package:
                    for ecosystem_product in product_list:
                        ecosystem, product = ecosystem_product.split('/')
                        if ecosystem == language and product == package:
                            product_update.append(ecosystem_product)
                            
        print("22222",niah_id_update)
        print("22222",product_update)

        if len(niah_id_update) > 0 or len(product_update) > 0:

            if len(niah_id_update) > 0:
                for id in niah_id_update:
                    niah_id_data.append(get_niah_id_data(id))
            if len(product_update) > 0:
                for e_p in product_update:
                    eco_prod_data.append(get_eco_prod_data(e_p))


            res = {}
            res["receiver"] = recipient
            if len(niah_id_update) > 0 or len(product_update) > 0:
                res["id"] = len(update_report) + 1
            res["niah_updates"] = niah_id_data
            res["eco_prod_updates"] = eco_prod_data 

            update_report.append(res)

    return jsonify(update_report)
        
        
@app.route('/api/v1/license/ecosystem/<ecosystem>', methods = ['GET'])
def get_default_license_echosystem(ecosystem):
    if request.method == 'GET':

        ecosystems = ['java', 'javascript', 'php', 'python' , 'rust', 'dart', 'ruby', 'elixir', 'c']
        ecosystem_platforms = ['ubuntu', 'debian', 'suse_linux']
        
        if ecosystem in ecosystems:
            eco_type = "dependencies"
        
        if ecosystem in ecosystem_platforms:
            eco_type = "platform"
        

        results = {}
        results['columns'] = []

        resCol = {}

        rescol = {}
        rescol['title'] = "Package"
        rescol['field'] = "name"
        results['columns'].append(rescol)

        resCol = {}
        resCol['title'] = "License"
        resCol['field'] = "license"
        results['columns'].append(resCol)

        resCol = {}
        resCol['title'] = "URL"
        resCol['field'] = "home_page"
        results['columns'].append(resCol)

        resCol = {}
        resCol['title'] = "Version"
        resCol['field'] = "version"
        results['columns'].append(resCol)
        
        if request.args.get('offset'):
            pageoffset = request.args.get('offset')
            if request.args.get('limit'):
                rowlimit = request.args.get('limit')
            else:
                rowlimit = 50
        else:
            pageoffset = 0
            rowlimit = 50

        rowlimit = int(pageoffset) + int(rowlimit)

        if ecosystem == "python":
            filename = "pypi_license_db.json"

        if ecosystem == "php":
            filename = "composer_license_db.json"

        if ecosystem == "java":
            filename = "maven_license_db.json"

        if ecosystem == "javascript":
            filename = "npm_license_db.json"

        if ecosystem == "ubuntu":
            filename = "ubuntu_license_db.json"

        if ecosystem == "debian":
            filename = "debian_license_db.json"

        if ecosystem == "rust":
            filename = "crates_license_db.json"

        if ecosystem == "dart":
            filename = "pub_license_db.json"

        if ecosystem == "ruby":
            filename = "ruby_license_db.json"

        if ecosystem == "elixir":
            filename = "hex_license_db.json"

        if ecosystem == "c":
            filename = "nuget_license_db.json"

        if ecosystem == "suse_linux":
            filename = "suse_license_db.json"

        with open ("/var/DB/license/%s" % filename, "r") as f:
            jsondata = json.load(f)

        jsondata = jsondata['results'] 

        results['total'] = len(jsondata)
        results['rowlimit'] = rowlimit
        results['data'] = jsondata[int(pageoffset):int(rowlimit)]
        
        return jsonify(results)


@app.route('/api/v1/license/ecosystem/<ecosystem>/<product>', methods = ['GET'])
def get_default_license_package_echosystem(ecosystem, product):
    if request.method == 'GET':

        ecosystems = ['java', 'javascript', 'php', 'python']
        ecosystem_platforms = ['ubuntu', 'debian']
        
        if ecosystem in ecosystems:
            eco_type = "dependencies"
        
        if ecosystem in ecosystem_platforms:
            eco_type = "platform"

        if '____' in str(product):
            product = product.replace("____", "/")


        results = {}
    
        results['columns'] = []

        rescol = {}
        rescol['title'] = "Package"
        rescol['field'] = "niah_id"
        results['columns'].append(rescol)

        resCol = {}
        resCol['title'] = "License"
        resCol['field'] = "severity"
        results['columns'].append(resCol)

        if eco_type == "platform":
            resCol = {}
            resCol['title'] = "OSNAME"
            resCol['field'] = "platform"
            results['columns'].append(resCol)
        else:
            resCol = {}
            resCol['title'] = "Installer"
            resCol['field'] = "installer"
            results['columns'].append(resCol)

        resCol = {}
        resCol['title'] = "Version"
        resCol['field'] = "version"
        results['columns'].append(resCol)


        if request.args.get('offset'):
            pageoffset = request.args.get('offset')
            if request.args.get('limit'):
                rowlimit = request.args.get('limit')
            else:
                rowlimit = 50
        else:
            pageoffset = 0
            rowlimit = 50

        rowlimit = int(pageoffset) + int(rowlimit)

        res = get_json_feeds()
        license_info = res.get_package_license_details(product, ecosystem)

        if license_info:
            results['license_info'] = license_info
        else:
            results['license_info'] = {}

        return jsonify(results)



@app.route('/api/v1/license/update', methods = ['GET'])
def get_license_update():
    if request.method == 'GET':
        results = {}
        results['daywise'] = []

        with open("/var/DB/license/update/lic_today.json", "r") as f:
            jsondata = json.load(f)
            
    
        for data in jsondata:
            print(data)
            
            package = data['package']
            description = data['description']
            ecosystem = data['ecosystem']
            license = data['license']
            version = data['version']

            res = {}
            res['description'] = description
            res['package'] = package
            res['ecosystem'] = ecosystem
            res['license'] = license
            res['version'] = version
            results['daywise'].append(res)

        return results
    

@app.route('/api/sbom/upload', methods = ['POST'])
def sbom_upload():
    print("SBOM UPLOAD..")
    print("files ----", request.args)
    

    type = request.args.get('type')
    distro = request.args.get('distro')
    filename = request.args.get('filename')
    # sbom_file = request.args.get('sbom_file')
    api_key = request.args.get('api-key')
    user_id = get_user_id(api_key)
    print("uuuuu", user_id)

    sbom_dir = '/home/niah/niah-license/static/report/%s/sbom' % user_id
    unique_file_name = request.args.get('unique_file_name')
    # sbom_file = "%s_%s" % (sbom_file, str(datetime.datetime.now()).replace(" ",""))

    if not os.path.exists(sbom_dir):
        os.makedirs(sbom_dir)

    print(os.getcwd())

  
    filepath = "/home/ftpuser/uploads"
   
    
    # Celery('tasks', backend='amqp', broker='amqp://%s:%s@%s/%s' % (celery_username, celery_password, celery_hostname, celery_vhost))
    if type == 'file':
        res = send_task("tasks.sbom_file_default", [filename, filepath, sbom_dir,  unique_file_name])
    elif type == 'dockerfile':
        res = send_task("tasks.sbom_docker_file_default", [filename, filepath, sbom_dir,  unique_file_name])
    elif type == 'dpkg':
        res = send_task("tasks.sbom_dpkg_file_default", [distro, filepath, filename, sbom_dir, unique_file_name])

    time.sleep(2)

    # cmd = "rm -rf %s" % tempdir
    # print(cmd)
    # status, output = getstatusoutput(cmd)

    results_id = res.id

    res = AsyncResult(results_id)

    if res.state == "SUCCESS":
        results = {}
        results['results'] = res.result
        results['results_id'] = results_id
        results['status'] = res.state
        print(results)
        return jsonify(results)
    else:
        results = {}
        results['results'] = res.result
        results['results_id'] = results_id
        results['status'] = res.state
        print(results)
        return jsonify(results)

    
@app.route('/api/sbom/repo', methods = ['POST'])
def sbom_repo():
    if request.method == 'POST':
        print("r ---", request.args)
        if 'git_repo_url' in request.args:
            git_repo_url = request.args.get('git_repo_url')
        if 'docker_repo_name' in request.args:
            docker_repo_name = request.args.get('docker_repo_name')

        repo_type = request.args.get('repo_type')
        sbom_file = request.args.get('sbom_file')
        api_key = request.args.get('api-key')
        unique_file_name = request.args.get('unique_file_name')
        user_id = get_user_id(api_key)

        git_repo_url = git_repo_url.replace('_____', '/')
        git_repo_url = git_repo_url.replace('.....', ':')

        print("Changed..", git_repo_url)

        sbom_dir = '/home/niah/niah-license/static/report/%s/sbom' % user_id
        sbom_file = "%s_%s" % (sbom_file, str(datetime.datetime.now()).replace(" ",""))

        if not os.path.exists(sbom_dir):
            os.makedirs(sbom_dir)

        if repo_type == "docker":
            res = send_task("tasks.sbom_docker_repo_default",[docker_repo_name, sbom_dir, unique_file_name])
        elif repo_type == "git":
            res = send_task("tasks.sbom_git_repo_default",[git_repo_url, sbom_dir, unique_file_name])

        results_id = res.id

        res = AsyncResult(results_id)
        print("res", res.result)

        if res.state == "SUCCESS":
            results = {}
            results['results'] = res.result
            results['results_id'] = results_id
            results['status'] = res.state
            return jsonify(results)
        else:
            results = {}
            results['results'] = res.result
            results['results_id'] = results_id
            results['status'] = res.state
            return jsonify(results)

@app.route('/api/sbom/status/check', methods = ['POST'])
def sbom_status():
    results_id = request.args.get('results_id')

    res = AsyncResult(results_id)

    if res.state == "SUCCESS":
        results = {}
        results['results'] = res.result
        results['results_id'] = results_id
        results['status'] = res.state
        return jsonify(results)
    else:
        results = {}
        results['results'] = res.result
        results['results_id'] = results_id
        results['status'] = res.state
        return jsonify(results)


@app.route('/api/sbom/list', methods = ['POST'])
def sbom_list():
    if request.method == 'POST':
        api_key = request.args.get('api-key')
        user_id = get_user_id(api_key)

        user_sbom_path = '/home/niah/niah-license/static/report/%s/sbom' % user_id
        files = os.listdir(user_sbom_path) 
        return jsonify(files)


@app.route('/api/sbom/download', methods = ['POST'])
def sbom_download():
    if request.method == 'POST':
        api_key = request.args.get('api-key')
        user_id = get_user_id(api_key)
        sbom_filename = request.args.get('sbom_filename')

        sbom_file_path = '/home/niah/niah-license/static/report/%s/sbom/%s' % (user_id, sbom_filename)
        if os.path.isfile(sbom_file_path):
           return send_file(sbom_file_path, as_attachment=True)
        else:
            return "File not found..!!"
    else:
        return "Invalid Request Method.." 
    

@app.route('/api/sbom/delete', methods = ['POST'])
def sbom_delete():
    if request.method == 'POST':
        api_key = request.args.get('api-key')
        user_id = get_user_id(api_key)
        sbom_filename = request.args.get('sbom_filename')

        sbom_file_path = '/home/niah/niah-license/static/report/%s/sbom/%s' % (user_id, sbom_filename)
        
        if os.path.exists(sbom_file_path):
           os.remove(sbom_file_path)
           return "File deleted Successfully..!!"
        
        else:
            return "File not found..!!"
    
    else:
        return "Invalid Request Method.." 
    
@app.route('/api/cve/update', methods = ['POST'])
def cve_update():
    if request.method == 'POST':  

        print(request.args)  
        api_key = request.args.get('api-key')
        start_date = request.args.get('start_date') # 2023-02-01
        end_date = request.args.get('end_date') # 2023-02-01

        user_id = get_user_id(api_key)


        type_s = "api"
        dst_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        api_type = "ONLINE_CVE_UPDATES"
        # filename = datetime.today().strftime("%Y-%m-%d_%H-%M-%S") + '.json'
        filename = "%s_%s.json" % (start_date, end_date)
        updateCounter(type_s, dst_ip, user_id, api_type, filename)


        if os.path.exists("/var/DB/online_update/%s" % filename):
            with open("/var/DB/online_update/%s" % filename, 'r') as f:
                jsondata = json.load(f)

            return jsondata
        else:
            res = send_task("tasks.get_committed_files_in_period",[start_date, end_date])

            results_id = res.id


            time.sleep(5)
            res = AsyncResult(results_id)

            if res.state == "SUCCESS":
                results = {}
                results['results'] = res.result
                results['results_id'] = results_id
                results['filename'] = filename
                results['status'] = "Task Finished.."
                # print(results)

                # with open("/var/DB/online_update/%s.json", "w") as outfile:
                #     json.dump(res.result, outfile, indent = 2)

                return jsonify(results)
            else:
                results = {}
                results['results'] = res.result
                results['results_id'] = results_id
                results['filename'] = filename
                results['status'] = "Task Running.."
                # print(results)
                return jsonify(results)


@app.route('/api/onlineupdate/status/check', methods = ['POST'])
def onlineupdate_check():
    results_id = request.args.get('results_id')
    filename = request.args.get('filename')

    res = AsyncResult(results_id)

    if res.state == "SUCCESS":
        results = {}
        
        output = res.result

        with open("/var/DB/online_update/%s" % filename, "w") as outfile:
            json.dump(output, outfile, indent=2)

        with open("/var/DB/online_update/%s" % filename, "r") as f:
            jsondata = json.load(f)

        results['results'] = jsondata
        results['results_id'] = results_id
        results['filename'] = filename
        results['status'] = "Task Finished.."

        return jsonify(results)
    
    else:
        results = {}
        results['results'] = res.result
        results['results_id'] = results_id
        results['filename'] = filename
        results['status'] = "Task Running.."
        return jsonify(results)



@app.route('/api/dashboard/severitychart', methods = ['GET'])
def dashboard_severitychart():
    if request.method == 'GET': 
    
        with open('/var/DB/online_update/severity_dataset.json', "r") as f:
            chart_data = json.load(f)

        return chart_data


@app.route('/api/v1/gen/report', methods = ['POST'])
def generate_report():
    if request.method == 'POST':

        api_key = request.args.get('api-key')
        start_date = request.args.get('start_date') # 2023-02-01
        end_date = request.args.get('end_date') # 2023-02-01

        user_id = get_user_id(api_key)

        type_s = "api"
        dst_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        api_type = "ONLINE_REPORT_GENERATE"
        # filename = datetime.today().strftime("%Y-%m-%d_%H-%M-%S") + '.json'
        
        filename = "%s_%s.json" % (start_date, end_date)

        report_dir = '/home/niah/niah-license/static/report/%s/reports' % user_id
        updateCounter(type_s, dst_ip, user_id, api_type, filename)
        if os.path.exists("/var/DB/online_update/%s" % filename):
            with open("/var/DB/online_update/%s" % filename, 'r') as f:
                jsondata = json.load(f)

            return jsondata
        else:
            res = send_task("tasks.get_committed_files_in_period",[start_date, end_date])


            results_id = res.id

            time.sleep(5)
            res = AsyncResult(results_id)

            if res.state == "SUCCESS":
                results = {}
                results['results'] = res.result
                results['results_id'] = results_id
                results['filename'] = filename

                with open("%s/%s" % (report_dir, filename), "w") as outfile:
                    json.dump(res.result, outfile, indent=2)

                results['status'] = "Task Finished.."
                
                return jsonify(results)
            else:
                results = {}
                results['results'] = res.result
                results['results_id'] = results_id
                results['filename'] = filename
                results['status'] = "Task Running.."
                # print(results)
            return jsonify(results)


@app.route('/api/v1/statuscheck/report', methods = ['POST'])
def report_status():
    if request.method == 'POST':
        results_id = request.args.get('results_id')
        api_key = request.args.get('api-key')
        filename = request.args.get('filename')
        user_id = get_user_id(api_key)

        report_dir = '/home/niah/niah-license/static/report/%s/reports' % user_id
        
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)

        res = AsyncResult(results_id)

        if res.state == "SUCCESS":
            results = {}
            results['results'] = res.result
            results['results_id'] = results_id

            output = res.result

            with open("%s/%s" % (report_dir, filename), "w") as outfile:
                json.dump(output, outfile, indent=2)

            results['status'] = "Task Finished.."
            return jsonify(results)
        else:
            results = {}
            results['results'] = res.result
            results['results_id'] = results_id
            results['status'] = "Task Running.."
            return jsonify(results)
    

@app.route('/api/v1/get/report', methods = ['POST'])
def get_report():
    if request.method == 'POST':
        api_key = request.args.get('api-key')
        filename = request.args.get('filename')
        user_id = get_user_id(api_key)

        report_dir = '/home/niah/niah-license/static/report/%s/reports' % user_id

        with open("%s/%s" % (report_dir, filename), "r") as f:
            jsondata = json.load(f)

        return jsonify(jsondata)


@app.route('/api/v1/delete/report', methods = ['POST'])
def delete_report():
    if request.method == 'POST':

        api_key = request.args.get('api-key')
        filename = request.args.get('filename')
        user_id = get_user_id(api_key)

        report_dir = '/home/niah/niah-license/static/report/%s/reports' % user_id

        target_file = "%s/%s" % (report_dir, filename)

        if os.path.exists(target_file):

            cmd = "rm -rf %s" % target_file
            output = getoutput(cmd)

            res = {"msg" : "Report Deleted Successfully..!!"}

        else:
            res = {"msg" : "Report file not found..!!"}


        return res


@app.route('/api/v1/scan/<domain>/<ecosystem>', methods = ['POST'])
def get_scan_echosystem(domain, ecosystem):
    if request.method == 'POST':
        from datetime import datetime

        req_data = request.get_json()
        api_key = req_data['api-key']
        user_id = get_user_id(api_key)

        if not user_id:
            results['message'] = "API Key incorrect, Please contact support!!"
            results['error'] = True
            return results
        
        if not check_user_active(user_id):
            results['message'] = "User ID is not active, Please contact support!!"
            results['error'] = True
            return results

        type_s = "api"
        dst_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        api_type = "SCANNER_ECOSYSTEM"

        filename = datetime.today().strftime("%Y-%m-%d_%H-%M")
        updateCounter(type_s, dst_ip, user_id, api_type, filename)
        
        results = {}
        results['data'] = []

        filename = "%s.json" % ecosystem
        
        ecosystems = ['c#', 'c', 'dart', 'elixir', 'go', 'java', 'javascript', 'php', 'python', 'ruby', 'rust']
        ecosystem_platforms = ['ubuntu', 'debian', 'rhel', 'oracle_linux']
        unknown_vulns = ['noncve']
        
        if ecosystem not in ecosystem_platforms and ecosystem not in ecosystems and ecosystem not in unknown_vulns:
            results['error'] = "ecosystem not supported"
            return jsonify(results)

        if ecosystem in ecosystems:
            eco_type = "dependencies"
        
        if ecosystem in ecosystem_platforms:
            eco_type = "platform"

        if ecosystem in unknown_vulns:
            eco_type = "noncve"

        if eco_type == "dependencies":
            for dep_file in os.listdir("/var/DB/feeds/language/"):
                if filename == dep_file:
                    with open("/var/DB/feeds/language/%s" % filename, "r") as f:
                        jsondata1 = json.load(f)
                    
                    jsondata1['results'].sort(key=lambda x: x["modified"], reverse=True)
                    jsondata1 = jsondata1['results']
                    
                    #with open("/var/DB/feeds/non-cve/noncve_feed.json", "r") as f:
                    #    jsondata2 = json.load(f)
                    
                    #jsondata2 = jsondata2['results']

                    #jsondata2 = list(filter(lambda x:(ecosystem == x['language']),jsondata2))
                    #jsondata = jsondata1 + jsondata2
                    jsondata = jsondata1
                    
                    results['data'] = jsondata
      
        if eco_type == "platform":
            for dep_file in os.listdir("/var/DB/feeds/platform/"):
                if ecosystem == dep_file:
                    if dep_file == "oracle_linux":
                        dep_file = "oracle"

                    if domain not in ecosystem_platforms:
                        filepath = "/var/DB/feeds/platform/%s/%s.json" % (dep_file, domain)
                        if os.path.isfile(filepath):
                            with open(filepath, "r") as f:
                                jsondata = json.load(f)
                            
                            jsondata = jsondata['vulnerabilities']
                    else:
                        platform_data = []
                        
                        filepath = "/var/DB/feeds/platform/%s/%s.json" % (dep_file, dep_file)
                        with open(filepath, "r") as f:
                            jsondata = json.load(f)

                        for key, value in jsondata.items():
                            if isinstance(value, list):
                                platform_data.extend(value)
                                jsondata = platform_data                    
                    
                    results['data'] = jsondata
        
        return jsonify(results)


@app.route('/api/v1/get/report/today', methods = ['POST'])
def get_today_report():

    with open("/var/DB/online_update/daily_dash_data.json", "r") as f:
        jsondata = json.load(f)

    # jsondata = get_dashboard_data(jsondata)

    return jsonify(jsondata)


@app.route('/api/v1/get/apikey', methods = ['POST'])
def get_api_key():

    user_id = getUserID()

    query = "select api_key from license_master_db where user_id='%s'" % user_id
    print(query)
    g.cursor.execute(query)
    apiDB = g.cursor.fetchall();

    api_key = apiDB[0][0]

    return api_key
    

@app.route('/api/v1/notification', methods = ['POST'])
def get_notifications():
    if request.method == 'POST':
        req_data = request.get_json()
        notifications = []
        api_key = req_data['api_key']


        query = "select user_id from license_master_db where api_key='%s'" % api_key
        print(query)
        g.cursor.execute(query)
        userDB = g.cursor.fetchall();

        user_id = userDB[0][0]


        query = "select msg from notification_tab where user_id='%s'" % user_id
        print(query)
        g.cursor.execute(query)
        msgDB = g.cursor.fetchall();

        if len(msgDB) > 0:
            print(len(msgDB))
            print("======", msgDB)

            message = msgDB[0][0]
            print(message)

            return jsonify(message)
        else:
            res = {}
            res['message'] = "No notifications available..!!"
            return jsonify(res)
        
    else:
        res = {}
        res['message'] = "Invalid Request Method"
        return jsonify(res)


@app.route('/api/v1/advisor/ecolist', methods = ['POST'])
def get_advisor_ecolist():
    if request.method == 'POST':

        ecosystems_list = ['pypi', 'maven', 'composer', 'crates', 'npm', 'nuget', 'hex', 'ruby', 'pub']

        return jsonify(ecosystems_list)


def check_repo_info(ecosystem, package_data):

    if ecosystem == "pypi":
        if "repo_info" in package_data['info']:
            repo_info = len(package_data['info']['repo_info'])    
        else:
            repo_info = 0
        
    if ecosystem == "ruby":
        if "repo_info" in package_data:
            repo_info = len(package_data['repo_info'])   
        else:
            repo_info = 0

    if ecosystem == 'npm':
        
        if "repo_info" in package_data:
            repo_info = len(package_data['repo_info'])   
        else:
            repo_info = 0 

    if ecosystem == 'hex':
        if "repo_info" in package_data:
            repo_info = len(package_data['repo_info'])   
        else:
            repo_info = 0

    if ecosystem == 'nuget':
        if "repo_info" in package_data:
            repo_info = len(package_data['repo_info'])   
        else:
            repo_info = 0

    if ecosystem == 'pub':
        package_data = eval(package_data)
        if "repo_info" in package_data:
            repo_info = len(package_data['repo_info'])   
        else:
            repo_info = 0

    if ecosystem == 'crates':
        if "repo_info" in package_data['crate']:
            repo_info = len(package_data['crate']['repo_info']) 
        else:
            repo_info = 0

    if ecosystem == 'composer':
        if "repo_info" in package_data:
            repo_info = len(package_data['repo_info'])   
        else:
            repo_info = 0

    if ecosystem == 'ubuntu':
        repo_info = 1

    if ecosystem == 'debian':
        repo_info = 1

    if ecosystem == 'maven':
        repo_info = 1

    if repo_info > 0:
        return "yes"
    else:
        return "no"


    


@app.route('/api/v1/advisor/eco/pack', methods = ['POST'])
def get_advisor_ecopack():
    if request.method == 'POST':

        req_data = request.get_json()

        ecosystem = req_data['ecosystem']
        package = req_data['package']

        print(req_data)

        if ecosystem == 'composer':
            package = str(package).replace("/", "_")

        pack_file = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s.json" % (ecosystem, package.lower(), package.lower())

        print(pack_file)
        if os.path.exists(pack_file):
            with open(pack_file, "r") as f:
                package_data = json.load(f)

            repo_info = check_repo_info(ecosystem, package_data)

            if repo_info == "yes":
                final_result = get_pckg_data(ecosystem, package_data, package)
                return jsonify(final_result)
            
            else:
                res = send_task("tasks.advisor_ecopack", [ecosystem, package])
                result_id = res.id

                output = {}
                output['result_id'] = result_id 

                return output
            
        else:
            res = send_task("tasks.advisor_ecopack", [ecosystem, package])
            result_id = res.id

            output = {}
            output['result_id'] = result_id

            return output


def get_pckg_data(ecosystem, package_data, package):
    display_data = {}
    pack_datails = {}

    eco_dir = "/mnt/niahdb/niah-advisor/niah_pack/%s" % ecosystem
    if not os.path.exists(eco_dir):
        os.mkdir(eco_dir)
    
    package_dir = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s" % (ecosystem, package)

    pack_datails['pack_info'] = {}
    pack_datails['vuln_report'] = {}
    
    if ecosystem == "pypi":
        print(package_data)
        display_data["p_name"] = package_data['info']['name']
        display_data["ecosystem"] = ecosystem
        display_data["related"] = package_data['info']['keywords']
        display_data["dependency"] = package_data['info']['dependency']
        display_data["dependents"] = package_data['info']['dependents']
        display_data["dep_tree"] = package_data['info']['dep_tree']
        display_data["dependency"] = package_data['info']['dependency']
        display_data["dependents"] = package_data['info']['dependents']
        display_data["dep_tree"] = package_data['info']['dep_tree']
        display_data["latest_version"] = package_data['info']['version']
        display_data["all_versions"] = package_data['info']['all_tags']
        display_data["description"] = package_data['info']['summary']
        if 'github_url' in package_data['info']:
            display_data["github_url"] = package_data['info']['github_url']
        elif 'project_urls' in package_data['info']:
            display_data["github_url"] = package_data['info']['project_urls']['Code']
        else:
            display_data["github_url"] = ''
        display_data["download_url"] = package_data['info']['download_url']
        display_data["home_page"] = package_data['info']['home_page']
        display_data["license"] = package_data['info']['license']
        display_data["repo_info"] = package_data['info']['repo_info']
        # display_data["healthscore"] = package_data['info']['healthscore']


        pack_datails['pack_info'] = display_data

    if ecosystem == "ruby":
        display_data["p_name"] = package_data['packagename']
        display_data["ecosystem"] = ecosystem
        display_data["related"] = ""
        display_data["dependency"] = package_data['dependency']
        display_data["dependents"] = package_data['dependents']
        display_data["dep_tree"] = package_data['dep_tree']
        display_data["latest_version"] = package_data['latest_version']
        display_data["all_versions"] = package_data['versions']
        display_data["description"] = package_data['description']
        display_data["github_url"] = package_data['github_url']
        display_data["download_url"] = package_data['DownloadURL']
        display_data["home_page"] = package_data['HomeURL']
        display_data["license"] = package_data['license']
        display_data["repo_info"] = package_data['repo_info']

        pack_datails['pack_info'] = display_data

    if ecosystem == "maven":
        display_data["p_name"] = package
        display_data["ecosystem"] = ecosystem
        display_data["related"] = ""
        display_data["dependency"] = package_data['dependency']
        display_data["dependents"] = package_data['dependents']
        display_data["dep_tree"] = package_data['dep_tree']
        display_data["latest_version"] = package_data['version']
        display_data["all_versions"] = package_data['releases']
        display_data["description"] = package_data['description']
        display_data["github_url"] = package_data['home_page']
        display_data["download_url"] = package_data['home_page']
        display_data["home_page"] = package_data['home_page']
        display_data["license"] = package_data['license']
        # display_data["healthscore"] = package_data['healthscore']

        pack_datails['pack_info'] = display_data

    if ecosystem == 'npm':
        display_data["p_name"] = package_data['name']
        display_data["ecosystem"] = ecosystem
        display_data["related"] = ""
        display_data["dependency"] = package_data['dependency']
        display_data["dependents"] = package_data['dependents']
        display_data["dep_tree"] = package_data['dep_tree']
        display_data["latest_version"] = package_data['dist-tags']['latest']
        display_data["all_versions"] = package_data['versions_list']
        display_data["description"] = package_data['description']
        display_data["github_url"] = package_data['repository']['url']
        display_data["download_url"] = package_data['homepage']
        display_data["home_page"] = package_data['homepage']
        display_data["license"] = package_data['license']
        display_data["repo_info"] = package_data['repo_info']
        # display_data["healthscore"] = package_data['healthscore']

        pack_datails['pack_info'] = display_data

    if ecosystem == 'hex':

        print("Selecting display data for hex")
        # print(package_data)
        display_data["p_name"] = package_data['packagename']
        display_data["ecosystem"] = ecosystem
        display_data["related"] = ""
        display_data["dependency"] = package_data['dependency']
        display_data["dependents"] = package_data['dependents']
        display_data["dep_tree"] = package_data['dep_tree']
        display_data["latest_version"] = package_data['latest_version']
        display_data["all_versions"] = package_data['versions']
        display_data["description"] = package_data['description']
        display_data["github_url"] = package_data['github_url']
        display_data["download_url"] = package_data['github_url']
        display_data["home_page"] = package_data['github_url']
        display_data["license"] = package_data['license']
        display_data["repo_info"] = package_data['repo_info']
        # display_data["healthscore"] = package_data['healthscore']

        pack_datails['pack_info'] = display_data

    if ecosystem == 'nuget':

        display_data["p_name"] = package_data['packagename']
        display_data["ecosystem"] = ecosystem
        display_data["related"] = ""
        display_data["dependency"] = package_data['dependency']
        display_data["dependents"] = package_data['dependents']
        display_data["dep_tree"] = package_data['dep_tree']
        display_data["latest_version"] = package_data['latest-version']
        display_data["all_versions"] = package_data['versions']
        display_data["description"] = package_data['description']
        display_data["github_url"] = package_data['Source-repo']
        display_data["download_url"] = package_data['DownloadURL']
        display_data["home_page"] = package_data['project-website']
        display_data["license"] = package_data['license']
        display_data["repo_info"] = package_data['repo_info']
        # display_data["healthscore"] = package_data['healthscore']

        pack_datails['pack_info'] = display_data

    if ecosystem == 'pub':
        print(type(package_data))
        display_data["p_name"] = package_data['package_name']
        display_data["ecosystem"] = ecosystem
        display_data["related"] = ""
        display_data["dependency"] = package_data['dependency']
        display_data["dependents"] = package_data['dependents']
        display_data["dep_tree"] = package_data['dep_tree']
        display_data["latest_version"] = package_data['latest_version']
        display_data["all_versions"] = package_data['version']
        display_data["description"] = package_data['description']
        display_data["github_url"] = package_data['github_url']
        display_data["download_url"] = package_data['home_url']
        display_data["home_page"] = package_data['home_url']
        display_data["license"] = package_data['license']
        display_data["repo_info"] = package_data['repo_info']
        # display_data["healthscore"] = package_data['healthscore']

        pack_datails['pack_info'] = display_data

    if ecosystem == "ubuntu":
        display_data = {}
        display_data["p_name"] = package
        display_data["ecosystem"] = ecosystem
        display_data["related"] = ""
        display_data["latest_version"] = package_data['version']
        display_data["all_versions"] = package_data['releases']
        display_data["description"] = package_data['description']
        display_data["github_url"] = package_data['home_page']
        display_data["download_url"] = package_data['home_page']
        display_data["home_page"] = package_data['home_page']
        display_data["license"] = package_data['license']
        
        pack_datails['pack_info'] = display_data

    
    if ecosystem == "debian":
        display_data = {}
        display_data["p_name"] = package
        display_data["ecosystem"] = ecosystem
        display_data["related"] = ""
        display_data["latest_version"] = package_data['version']
        display_data["all_versions"] = package_data['releases']
        display_data["description"] = package_data['description']
        display_data["github_url"] = package_data['home_page']
        display_data["download_url"] = package_data['home_page']
        display_data["home_page"] = package_data['home_page']
        display_data["license"] = package_data['license']
        
        pack_datails['pack_info'] = display_data


    if ecosystem == 'crates':
        display_data["p_name"] = package_data['crate']['name']
        display_data["ecosystem"] = ecosystem
        display_data["related"] = ""
        display_data["dependency"] = []
        display_data["dependents"] = []
        display_data["dep_tree"] = []
        display_data["latest_version"] = package_data['crate']['newest_version']
        display_data["all_versions"] = package_data['crate']['all_versions']
        display_data["description"] = package_data['crate']['description']
        display_data["github_url"] = package_data['crate']['repository']
        display_data["download_url"] = package_data['crate']['homepage']
        display_data["home_page"] = package_data['crate']['homepage']
        display_data["license"] = package_data['crate']['license']
        display_data["repo_info"] = package_data['crate']['repo_info']
        # display_data["healthscore"] = package_data['crate']['healthscore']

        pack_datails['pack_info'] = display_data
    
    if ecosystem == 'composer':
        slash_pack = str(package).replace("_", "/")
        com_package = package_data['packages'][slash_pack][0]
        
        display_data = {}
        display_data["p_name"] = com_package['name']
        display_data["ecosystem"] = ecosystem
        display_data["related"] = ""
        display_data["dependency"] = com_package['dependency']
        display_data["dependents"] = com_package['dependents']
        display_data["dep_tree"] = com_package['dep_tree']
        display_data["latest_version"] = com_package['version']
        display_data["all_versions"] = package_data['all_versions']
        display_data["description"] = com_package['description']
        display_data["github_url"] = com_package['source']['url']
        display_data["download_url"] = com_package['homepage']
        display_data["home_page"] = com_package['homepage']
        display_data["license"] = com_package['license'][0]
        display_data["repo_info"] = package_data['repo_info']
        # display_data["healthscore"] = package_data['healthscore']

        pack_datails['pack_info'] = display_data
        try:
            with open("/mnt/niahdb/niah-advisor/niah_pack/%s/%s/vuln/%s_latest_report.json" % (ecosystem, package, package), "r") as f:
                package_report_data = json.load(f)
            pack_datails['vuln_report'] = package_report_data
        except:
            pack_datails['vuln_report'] = {}

    try:
        with open("%s/vuln/%s_latest_report.json" % (package_dir, package), "r") as f:
            package_report_data = json.load(f)
            pack_datails['vuln_report'] = package_report_data
    except:
        pass

    final_result = {}
    final_result['results'] = pack_datails

    return final_result

@app.route('/api/v1/advisor/eco/packtag', methods = ['POST'])
def get_advisor_ecopack_tag():
    if request.method == 'POST':

        req_data = request.get_json()

        ecosystem = req_data['ecosystem']
        package = req_data['package']
        tags = req_data['tags']

        print(req_data)


        report_name = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s/vuln/%s_%s_report.json" % (ecosystem, package, package, tags)
        if os.path.exists(report_name):
            with open(report_name, "r") as f:
                report_data = json.load(f)

            tag_report_details = {}
            tag_report_details['vuln_report'] = report_data

            output = {}
            output['results'] = tag_report_details

            return output

        else:
            if ecosystem == 'composer':
                package = str(package).replace("/", "_")

            pack_file = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s.json" % (ecosystem, package.lower(), package.lower())
            with open(pack_file, "r") as f:
                package_data = json.load(f)

                print(package_data)
            
            github_url = ''

            if ecosystem == "pypi":       
                if 'github_url' in package_data['info']:
                    github_url = package_data['info']['github_url']
                elif 'project_urls' in package_data['info']:
                    github_url = package_data['info']['project_urls']['Code']
            elif ecosystem == "ruby":
                github_url = package_data['github_url']
            elif ecosystem == 'npm':
                github_url = package_data['repository']['url']
            elif ecosystem == 'hex':
                github_url = package_data['github_url']
            elif ecosystem == 'nuget':
                github_url = package_data['Source-repo']
            elif ecosystem == 'pub':
                github_url = package_data['github_url']
            elif ecosystem == 'crates':
                github_url = package_data['crate']['repository']
            elif ecosystem == 'composer':
                slash_pack = str(package).replace("_", "/")
                com_package = package_data['packages'][slash_pack][0]
                github_url = com_package['source']['url']
            
            pack_datails = {}
            pack_datails['vuln_report'] = {}

            print("Github - %s" % github_url)
            if github_url:
                if re.findall(r'(https:\/\/github.com\/.*\/.*)\/',  str(github_url)):
                    github_url = re.findall(r'(https:\/\/github.com\/.*\/.*)\/',  str(github_url))[0]
                else:
                    github_url = github_url

                res = send_task("tasks.advisor_ecopack_tag", [ecosystem, package, tags, github_url])
                result_id = res.id

                output = {}
                output['result_id'] = result_id 
                output['error'] = "false"
            else:
                output = {} 
                output['error'] = "false"

            return output

    
@app.route('/api/v1/advisor/status/check', methods = ['POST'])
def advisor_status():
    results_id = request.args.get('results_id')
    print("1111111", results_id)

    res = AsyncResult(results_id)

    

    print(res)
    print(type(res.state))
    print(type(res.result))

    if res.state == "SUCCESS":
        output = res.result
        ecosystem = output['pack_info']['ecosystem']
        package = output['pack_info']['p_name']
    

        print("111", ecosystem, package)

        if ecosystem == "composer":
            if "/" in str(package):
                package = str(package).replace("/", "_")

        pack_file = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s.json" % (ecosystem, package.lower(), package.lower())

        print(pack_file)

        with open(pack_file, "r") as f:
            package_data = json.load(f)

        if ecosystem == "composer":
            if "_" in str(package):
                package = str(package).replace("_", "/")

        final_results = get_pckg_data(ecosystem, package_data, package)
        final_results['status'] = res.state
        final_results['results_id'] = results_id

        return jsonify(final_results)
    
    else:
        results = {}
        results['results_id'] = results_id
        results['status'] = res.state
        return results


@app.route('/api/v1/advisortag/status/check', methods = ['POST'])
def advisor_status_tag():
    results_id = request.args.get('results_id')
    print("1111111", results_id)

    res = AsyncResult(results_id)
    print(res)
    print(type(res.state))
    print(type(res.result))

    if res.state == "SUCCESS":
        results = {}
        results['results'] = res.result
        results['results_id'] = results_id
        results['status'] = res.state
        return results

    else:
        results = {}
        results['results_id'] = results_id
        results['status'] = res.state
        return results


    
    
@app.route('/api/v1/advisor/daily/update', methods = ['POST'])
def advisor_daily_update():

    
    with open("/home/niah/niah-license/advisor_updates.json", "r") as f:
        update_data = json.load(f)
    
    return jsonify(update_data)









if __name__ == "__main__":
    app.run('127.0.0.1', port=8080, debug=True)
