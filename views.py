# -*- coding: utf-8 -*-
# !/usr/bin/env python

# from app import app
# from flask import render_template, url_for
#
#
# @app.route('/')
# def index():
#     return render_template('searchBar.html', title="Welcome")



from flask import Flask
from flask import render_template, redirect, url_for, request, jsonify, session, redirect, url_for
from app import app
import sql_op
import CertSession_sql_op
import logging
from math import log
import datetime


logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    # filename='/root/passiveSSL/pro/flask/debug.log',
                    filename='./debug.log',
                    filemode='w')

global DEBUG
DEBUG = False

# from search_sql import search
# app = Flask(__name__)

# filter
def returnlogarr(arr):
    rel = []
    for item in arr:
        rel.append(log(item))
    return rel

def sqlTimeReadable(sqlTime):
    if len(sqlTime) == 15:
        return "{}-{}-{}, {}:{}:{}".format(sqlTime[0:4], sqlTime[4:6], sqlTime[6:8], sqlTime[8:10], sqlTime[10:12], sqlTime[12:14])
    else:
        return sqlTime

def bool_translator(val):
    if val == 1:
        return True
    elif val == 0:
        return False
    else:
        return "Undefined"

def str2List(s):
    arr = []
    for item in s.split('\''):
        if len(item) > 3:
            arr.append(item)
    return arr

def str2List2leafCert(s):
    arr = []
    for item in s.split('\''):
        if len(item) > 3:
            arr.append(item)
    return arr[0]


def readOpenSSL(path):
    with open(path) as f:
        content = f.read()
    return content

  def sqlTimeLeft(sqlTime):
    nowTime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    timeLeft = (int(sqlTime[0:4])-int(nowTime[0:4]))*365*24 + (int(sqlTime[4:6])-int(nowTime[5:7]))*24 + (int(sqlTime[6:8])-int(nowTime[8:10]))*1
    return timeLeft

env = app.jinja_env
env.filters['sqlTimeReadable'] = sqlTimeReadable #注册自定义过滤器
env.filters['bool_translator'] = bool_translator #注册自定义过滤器
env.filters['str2List'] = str2List #注册自定义过滤器
env.filters['readOpenSSL'] = readOpenSSL #注册自定义过滤器
env.filters['str2List2leafCert'] = str2List2leafCert #注册自定义过滤器
env.filters['returnlogarr'] = returnlogarr #注册自定义过滤器
env.filters['sqlTimeLeft'] = sqlTimeLeft


# index page
@app.route('/')
def index():
    rel = sql_op.get_cert_num()
    # 添加至 homepage 的 alert 信息栏中
    alert_dict = sql_op.get_alert_cert(self_signed=3, expired=4)
    # session_num = CertSession_sql_op.get_session_num()
    info = {}
    info["cert_num"] = rel["cert_num"]
    info["cert_num_inTrustStore"] = rel["cert_num_inTrustStore"]
    info["cert_growth"] = 1889
    info["alert_dict"] = alert_dict
    info["cert_num_byYears"] = [295, 380, 282, 429, 2659, 5791, 13866, 55947, 71930]
    info["isLog"] = True
    # info["session_num"] = session_num

    # project page
    return render_template('index.html', info=info)

    # test
    # return render_template('page-blank.html')

# SSL　cert search
@app.route('/search_SSL', methods=['POST', 'GET'])
def search_SSL():
    global DEBUG
    if DEBUG:
        logging.info("search_SSL():search_SSLCert.html will submit form to resultCertList()")
    return render_template('search_SSLCert.html')


# search result
@app.route('/resultCertList', methods=['POST', 'GET'])
def resultCertList():
    global DEBUG
    if DEBUG:
        logging.info("resultCertList():request.method: {}".format(request.method))
        logging.info("resultCertList():request.form: {}".format(request.form))
    if request.method == 'POST':
        if request.form['multiselect'] == 'all':
            if request.form['info']:
                sql_rel = sql_op.Cert_seach_Subject(request.form['info'])
                if DEBUG:
                    logging.info("resultCertList():request.form['multiselect']=='all'&&request.form['info'] exist: the number of sql results -- {}".format(len(sql_rel)))
                return render_template('result_cert_list.html', sql_arr=sql_rel)
            else:
                if DEBUG:
                    logging.warning("resultCertList():request.form['multiselect']=='all': cannot get request.form['info']")
                # error, cannot get request.form['info']
                pass
        elif request.form['multiselect'] == 'subject':
            if request.form['info']:
                sql_rel = sql_op.Cert_seach_Subject(request.form['info'])
                if DEBUG:
                    logging.info("resultCertList():request.form['multiselect']=='subject'&&request.form['info'] exist: the number of sql results -- {}".format(len(sql_rel)))
                return render_template('result_cert_list.html', sql_arr=sql_rel)
            else:
                if DEBUG:
                    logging.warning(
                        "resultCertList():request.form['multiselect']=='subject': cannot get request.form['info']")
                # error, cannot get request.form['info']
                pass
        elif request.form['multiselect'] == 'issuer':
            if request.form['info']:
                sql_rel = sql_op.Cert_seach_Issuer(request.form['info'])
                if DEBUG:
                    logging.info("resultCertList():request.form['multiselect']=='issuer'&&request.form['info'] exist: the number of sql results -- {}".format(len(sql_rel)))
                return render_template('result_cert_list.html', sql_arr=sql_rel)
            else:
                if DEBUG:
                    logging.warning(
                        "resultCertList():request.form['multiselect']=='issuer': cannot get request.form['info']")
                # error, cannot get request.form['info']
        elif request.form['multiselect'] == 'sha1':
            if request.form['info']:
                sql_rel = sql_op.Cert_seach_Sha1(request.form['info'])
                if DEBUG:
                    logging.info(
                        "resultCertList():request.form['multiselect']=='issuer'&&request.form['info'] exist: the number of sql results -- {}".format(
                            len(sql_rel)))
                return render_template('result_cert_list.html', sql_arr=sql_rel)
            else:
                if DEBUG:
                    logging.warning(
                        "resultCertList():request.form['multiselect']=='issuer': cannot get request.form['info']")
                # error, cannot get request.form['info']
                pass

    return render_template('result_cert_list.html')

# invalid cert search result
@app.route('/resultCertList_invalid', methods=['POST', 'GET'])
def resultCertList_invalid():
    global DEBUG
    if DEBUG:
        logging.info("resultCertList():request.method: {}".format(request.method))
        logging.info("resultCertList():request.form: {}".format(request.form))
    if request.method == 'POST':
        if request.form['multiselect'] == 'all':
            if request.form['info']:
                sql_rel = sql_op.Cert_seach_Subject(request.form['info'], isValid=False)
                if DEBUG:
                    logging.info("resultCertList():request.form['multiselect']=='all'&&request.form['info'] exist: the number of sql results -- {}".format(len(sql_rel)))
                return render_template('result_cert_list.html', sql_arr=sql_rel)
            else:
                if DEBUG:
                    logging.warning("resultCertList():request.form['multiselect']=='all': cannot get request.form['info']")
                # error, cannot get request.form['info']
                pass
        elif request.form['multiselect'] == 'subject':
            if request.form['info']:
                sql_rel = sql_op.Cert_seach_Subject(request.form['info'], isValid=False)
                if DEBUG:
                    logging.info("resultCertList():request.form['multiselect']=='subject'&&request.form['info'] exist: the number of sql results -- {}".format(len(sql_rel)))
                return render_template('result_cert_list.html', sql_arr=sql_rel)
            else:
                if DEBUG:
                    logging.warning(
                        "resultCertList():request.form['multiselect']=='subject': cannot get request.form['info']")
                # error, cannot get request.form['info']
                pass
        elif request.form['multiselect'] == 'issuer':
            if request.form['info']:
                sql_rel = sql_op.Cert_seach_Issuer(request.form['info'], isValid=False)
                if DEBUG:
                    logging.info("resultCertList():request.form['multiselect']=='issuer'&&request.form['info'] exist: the number of sql results -- {}".format(len(sql_rel)))
                return render_template('result_cert_list.html', sql_arr=sql_rel)
            else:
                if DEBUG:
                    logging.warning(
                        "resultCertList():request.form['multiselect']=='issuer': cannot get request.form['info']")
                # error, cannot get request.form['info']
        elif request.form['multiselect'] == 'sha1':
            if request.form['info']:
                sql_rel = sql_op.Cert_seach_Sha1(request.form['info'], isValid=False)
                if DEBUG:
                    logging.info(
                        "resultCertList():request.form['multiselect']=='issuer'&&request.form['info'] exist: the number of sql results -- {}".format(
                            len(sql_rel)))
                return render_template('result_cert_list.html', sql_arr=sql_rel)
            else:
                if DEBUG:
                    logging.warning(
                        "resultCertList():request.form['multiselect']=='issuer': cannot get request.form['info']")
                # error, cannot get request.form['info']
                pass

    return render_template('result_cert_list.html')

# cert info dispaly
@app.route('/result_Cert', methods=['POST', 'GET'])
def result_Cert():
    filename_sha1 = request.args.get("filename_sha1")
    if DEBUG:
        logging.info("result_Cert(): filename_sha1: {}".format(filename_sha1))
    rel = sql_op.Cert_result_filename_sha1(filename_sha1)
    print rel
    if DEBUG:
        logging.info("result_Cert(): sql result: {}".format(rel))
    if rel:
        return render_template('result_cert.html', cert=rel)
    else:
        return render_template('result_cert_NOtFOUND.html')

# SSL session search
@app.route('/search_session', methods=['POST', 'GET'])
def search_session():
    global DEBUG
    if DEBUG:
        logging.info("search_SSL():search_session.html will submit form to resultCertList()")
    return render_template('search_session.html')

# SSL session search result
@app.route('/resultSessionList', methods=['POST', 'GET'])
def resultSessionList():
    global DEBUG
    if DEBUG:
        logging.info("resultSessionList():request.method: {}".format(request.method))
        logging.info("resultSessionList():request.form: {}".format(request.form))
    if request.method == 'POST':
        if request.form['multiselect'] == 'IP':
            if request.form['info']:
                sql_rel = CertSession_sql_op.session_search_IP(request.form['info'])
                if DEBUG:
                    logging.info("resultSessionList():request.form['multiselect']=='IP'&&request.form['info'] exist: the number of sql results -- {}".format(len(sql_rel)))
                return render_template('result_session_list.html', sql_arr=sql_rel)
            else:
                if DEBUG:
                    logging.warning("resultSessionList():request.form['multiselect']=='IP': cannot get request.form['info']")
                # error, cannot get request.form['info']
                pass
        elif request.form['multiselect'] == 'ServerIP':
            if request.form['info']:
                sql_rel = CertSession_sql_op.session_search_serverIP(request.form['info'])
                if DEBUG:
                    logging.info("resultSessionList():request.form['multiselect']=='ServerIP'&&request.form['info'] exist: the number of sql results -- {}".format(len(sql_rel)))
                return render_template('result_session_list.html', sql_arr=sql_rel)
            else:
                if DEBUG:
                    logging.warning(
                        "resultSessionList():request.form['multiselect']=='ServerIP': cannot get request.form['info']")
                # error, cannot get request.form['info']
                pass
        elif request.form['multiselect'] == 'ClientIP':
            if request.form['info']:
                sql_rel = CertSession_sql_op.session_search_clientIP(request.form['info'])
                if DEBUG:
                    logging.info("resultSessionList():request.form['multiselect']=='ClientIP'&&request.form['info'] exist: the number of sql results -- {}".format(len(sql_rel)))
                return render_template('result_session_list.html', sql_arr=sql_rel)
            else:
                if DEBUG:
                    logging.warning(
                        "resultSessionList():request.form['multiselect']=='ClientIP': cannot get request.form['info']")
                # error, cannot get request.form['info']
        elif request.form['multiselect'] == 'ServerName':
            if request.form['info']:
                sql_rel = CertSession_sql_op.session_search_serverName(request.form['info'])
                if DEBUG:
                    logging.info(
                        "resultSessionList():request.form['multiselect']=='ServerName'&&request.form['info'] exist: the number of sql results -- {}".format(
                            len(sql_rel)))
                return render_template('result_session_list.html', sql_arr=sql_rel)
            else:
                if DEBUG:
                    logging.warning(
                        "resultSessionList():request.form['multiselect']=='ServerName': cannot get request.form['info']")
                # error, cannot get request.form['info']
                pass


# SSL　cert statistic
@app.route('/cert_stat', methods=['POST', 'GET'])
def cert_stat():
    global DEBUG
    if DEBUG:
        logging.info("cert_stat():cert_statistic.html will provide statitic info about SSL cert")
    # 传入 html
    data = {}
    # 证书总量增长趋势数据
    data["allCertNumByYears"] = {}
    data["allCertNumByYears"]["Yaxis"] = [295, 380, 282, 429, 2659, 5791, 13866, 55947, 71930]
    data["allCertNumByYears"]["title"] = "2010-2018 Certs Increasing Number"
    data["allCertNumByYears"]["Xtitle"] = "Years"
    data["allCertNumByYears"]["Ytitle"] = "Certs"
    # 叶证书总量增长趋势数据
    data["leafCertNumByYears"] = {}
    data["leafCertNumByYears"]["Yaxis"] = [52, 40, 35, 87, 1030, 4715, 11365, 52997, 69629]
    data["leafCertNumByYears"]["title"] = "2010-2018 Leaf Certs Increasing Number"
    data["leafCertNumByYears"]["Xtitle"] = "Years"
    data["leafCertNumByYears"]["Ytitle"] = "Leaf Certs"
    # CA证书总量增长趋势数据
    data["CACertNumByYears"] = {}
    data["CACertNumByYears"]["Yaxis"] = [16, 10, 11, 22, 16, 4, 4, 1, 0]
    data["CACertNumByYears"]["title"] = "2010-2018 CA Certs Increasing Number"
    data["CACertNumByYears"]["Xtitle"] = "Years"
    data["CACertNumByYears"]["Ytitle"] = "CA Certs"
    # 自签名证书总量增长趋势数据
    data["selfSignedCertNumByYears"] = {}
    data["selfSignedCertNumByYears"]["Yaxis"] = [241, 337, 247, 331, 1618, 1072, 2497, 2950, 2301]
    data["selfSignedCertNumByYears"]["title"] = "2010-2018 Self-Signed Certs Increasing Number"
    data["selfSignedCertNumByYears"]["Xtitle"] = "Years"
    data["selfSignedCertNumByYears"]["Ytitle"] = "Self-Signed Certs"
    # 失效证书总量增长趋势数据
    data["invalidCertNumByYears"] = {}
    data["invalidCertNumByYears"]["Yaxis"] = [241, 337, 247, 331, 1618, 1072, 2497, 2950, 2301]
    data["invalidCertNumByYears"]["title"] = "2010-2018 Invalid Certs Increasing Number"
    data["invalidCertNumByYears"]["Xtitle"] = "Years"
    data["invalidCertNumByYears"]["Ytitle"] = "Invalid Certs"
    # pie chart: CA证书数量，自签名证书数量，叶证书数量
    data["pie_chart_catalog"] = {}
    data["pie_chart_catalog"]["CA"] = 226
    data["pie_chart_catalog"]["leaf"] = 152804 - 226 - 12627
    data["pie_chart_catalog"]["self_signed"] = 12627


    return render_template('cert_statistic.html', data=data)

@app.route('/cert_alarm', methods=['POST', 'GET'])
def cert_alarm():
    sql_rel = sql_op.invalid_cert_search()
    return render_template('alarm_cert.html', sql_arr=sql_rel)

@app.route('/cert_alarm_stat', methods=['POST', 'GET'])
def cert_alarm_stat():
    # 传入 html
    data = {}
    # 自签名证书总量增长趋势数据
    data["selfSignedCertNumByYears"] = {}
    data["selfSignedCertNumByYears"]["Yaxis"] = [241, 337, 247, 331, 1618, 1072, 2497, 2950, 2301]
    data["selfSignedCertNumByYears"]["title"] = "2010-2018 Self-Signed Certs Increasing Number"
    data["selfSignedCertNumByYears"]["Xtitle"] = "Years"
    data["selfSignedCertNumByYears"]["Ytitle"] = "Self-Signed Certs"
    # 失效证书总量增长趋势数据
    data["invalidCertNumByYears"] = {}
    data["invalidCertNumByYears"]["Yaxis"] = [241, 337, 247, 331, 1618, 1072, 2497, 2950, 2301]
    data["invalidCertNumByYears"]["title"] = "2010-2018 Invalid Certs Increasing Number"
    data["invalidCertNumByYears"]["Xtitle"] = "Years"
    data["invalidCertNumByYears"]["Ytitle"] = "Invalid Certs"
    # pie chart: 有效证书数量，过期证书数量，自签名证书数量
    data["pie_chart_catalog"] = {}
    data["pie_chart_catalog"]["valid"] = 68487
    data["pie_chart_catalog"]["expired"] = 60735
    data["pie_chart_catalog"]["self_signed"] = 11939

    return render_template('cert_alarm_statistic.html', data=data)



