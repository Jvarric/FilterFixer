#!/usr/bin/env python3
from flask import render_template, request
from app import app
from filter_fixer import deduplicate, ip_convert, sender_convert, recip_convert, \
    content_convert, attach_convert


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/dedupe', methods=['GET', 'POST'])
def dedupe():
    title = 'Deduplication'
    if request.method == 'POST':
        data = request.form['filter-input']
        converted_data, dupes, dupe_num = deduplicate(data)
        return render_template('dedupe.html', title=title, output=converted_data, dupes=dupes, dupe_num=dupe_num)
    return render_template('dedupe.html', title=title, output='')


@app.route('/ip', methods=['GET', 'POST'])
def ip():
    title = 'IP filters'
    if request.method == 'POST':
        data = request.form['filter-input']
        converted_data, dupes, dupe_num = ip_convert(data)
        return render_template('ip.html', title=title, output=converted_data, dupes=dupes, dupe_num=dupe_num)
    return render_template('ip.html', title=title, output='')


@app.route('/send', methods=['GET', 'POST'])
@app.route('/sender', methods=['GET', 'POST'])
def sender():
    title = 'Sender filters'
    if request.method == 'POST':
        data = request.form['filter-input']
        converted_data, dupes, dupe_num = sender_convert(data)
        return render_template('sender.html', title=title, output=converted_data, dupes=dupes, dupe_num=dupe_num)
    return render_template('sender.html', title=title)


@app.route('/recip', methods=['GET', 'POST'])
@app.route('/recipient', methods=['GET', 'POST'])
def recipient():
    title = 'Recipient filters'
    if request.method == 'POST':
        data = request.form['filter-input']
        converted_data, dupes, dupe_num = recip_convert(data)
        return render_template('recipient.html', title=title, output=converted_data, dupes=dupes, dupe_num=dupe_num)
    return render_template('recipient.html', title=title)


@app.route('/content', methods=['GET', 'POST'])
def content():
    title = 'Content filters'
    if request.method == 'POST':
        data = request.form['filter-input']
        inbound, outbound, dupes_in, dupes_out, dupe_num = content_convert(data)
        return render_template('content.html', title=title, inbound=inbound, outbound=outbound, dupes_in=dupes_in,
                               dupes_out=dupes_out, dupe_num=dupe_num)
    return render_template('content.html', title=title)


@app.route('/attach', methods=['GET', 'POST'])
@app.route('/attachment', methods=['GET', 'POST'])
def attachment():
    title = 'Attachment filters'
    if request.method == 'POST':
        data = request.form['filter-input']
        converted_data, dupes, dupe_num = attach_convert(data)
        return render_template('attachment.html', title=title, output=converted_data, dupes=dupes, dupe_num=dupe_num)
    return render_template('attachment.html', title=title)
