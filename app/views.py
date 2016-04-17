from flask import render_template
from app import app

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/send')
@app.route('/sender')
def sender():
    title = 'Sender filters'
    return render_template('sender.html', title=title)


@app.route('/recip')
@app.route('/recipient')
def recipient():
    title = 'Recipient filters'
    return render_template('recipient.html', title=title)


@app.route('/ip')
def ip():
    title = 'IP filters'
    return render_template('ip.html', title=title)


@app.route('/content')
def content():
    title = 'Content filters'
    return render_template('content.html', title=title)


@app.route('/attach')
@app.route('/attachment')
def attachment():
    title = 'Attachment filters'
    return render_template('attachment.html', title=title)


