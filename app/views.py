from flask import render_template, request
from app import app
from filter_fixer import ip_gateway_to_service, sender_gateway_to_service, recip_gateway_to_service, \
    content_gateway_to_service, attach_gateway_to_service


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/ip', methods=['GET', 'POST'])
def ip():
    title = 'IP filters'
    if request.method == 'POST':
        data = request.form['filter-input']
        converted_data = ip_gateway_to_service(data)
        return render_template('ip.html', title=title, output=converted_data)
    return render_template('ip.html', title=title, output='')


@app.route('/send', methods=['GET', 'POST'])
@app.route('/sender', methods=['GET', 'POST'])
def sender():
    title = 'Sender filters'
    if request.method == 'POST':
        data = request.form['filter-input']
        converted_data = sender_gateway_to_service(data)
        return render_template('sender.html', title=title, output=converted_data)
    return render_template('sender.html', title=title)


@app.route('/recip', methods=['GET', 'POST'])
@app.route('/recipient', methods=['GET', 'POST'])
def recipient():
    title = 'Recipient filters'
    if request.method == 'POST':
        data = request.form['filter-input']
        converted_data = recip_gateway_to_service(data)
        return render_template('recipient.html', title=title, output=converted_data)
    return render_template('recipient.html', title=title)


@app.route('/content', methods=['GET', 'POST'])
def content():
    title = 'Content filters'
    if request.method == 'POST':
        data = request.form['filter-input']
        converted_data = content_gateway_to_service(data)
        return render_template('content.html', title=title, output=converted_data)
    return render_template('content.html', title=title)


@app.route('/attach', methods=['GET', 'POST'])
@app.route('/attachment', methods=['GET', 'POST'])
def attachment():
    title = 'Attachment filters'
    if request.method == 'POST':
        data = request.form['filter-input']
        converted_data = attach_gateway_to_service(data)
        return render_template('attachment.html', title=title, output=converted_data)
    return render_template('attachment.html', title=title)
