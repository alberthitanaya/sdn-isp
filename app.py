#!flask/bin/python
from flask import Flask, jsonify, g, abort, make_response, request
#from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.httpauth import HTTPBasicAuth
from flask.ext.sqlalchemy import SQLAlchemy
from passlib.apps import custom_app_context as pwd_context
import argparse, time
import os
import json
import re
import sqlite3

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:openflow#@localhost/sdn'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SECRET_KEY'] = 'some secret key for hashing'

db = SQLAlchemy(app)
auth = HTTPBasicAuth()

controller_ip = '149.171.189.1'     #IP address of SDN controller

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'))

class Customer(db.Model):
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True)
    switch_id = db.Column(db.String(23))
    
class SMP(db.Model):
    __tablename__ = 'smp'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))
    
    def hash_password(self,password):
        self.password_hash = pwd_context.encrypt(password)
        
    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})
        
    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None     # valid token, but it is expired
        except BadSignature:
            return None
        smp = SMP.query.get(data['id'])
        return smp

@auth.verify_password
def verify_password(username_or_token)
    smp = SMP.verify_auth_token(username_or_token)
    if not smp:
        #try to authenticate with username/password
        smp = SMP.query.filter_by(username=username_or_token).first()
        if not smp or not smp.verify_password(password):
            return False
    g.smp = smp
    return True
        
################ SUBSCRIBER REGISTRATION ######################
@app.route('/register', methods=['POST'])
def create_user():
    db = sqlite3.connect('users.db')
    c = db.cursor()
    if not request.json or not 'customer_id' in request.json:
        abort(400)
    table_entry = (request.json['subscriber_id'], request.json['customer_id'])
    c.execute('INSERT INTO users VALUES (?,?)', table_entry)
    db.commit()
    db.close()
    #print request.json['subscriber_id']
    #print request.json['customer_id']
    user = {
            'customer_id': request.json['customer_id'],
            'subscriber_id': request.json['subscriber_id']
    }
    return jsonify({'user': user}), 201
    
@app.route('/register/<int:cust_id>', methods=['GET'])
def check_cust_id(cust_id):
    db = sqlite3.connect('users.db')
    c = db.cursor()
    #check for customers in db
    c.execute('SELECT * FROM customers where customer_id = ?', (cust_id,))
    customer = c.fetchall()
    db.close()
    #print cust_id
    if not customer:
        result = "false"
    else:
        result = "true"
    response = make_response(jsonify({'result':result}))
    response.headers['Connection'] = 'Keep-Alive'
    return response

############# DEVICE DISCOVERY ###########################
@app.route('/devices/<int:subs_id>/', methods=['GET'])
def get_devices(subs_id):

    #command to get devices
    command = "curl -i http://%s:8080/wm/device/" % (controller_ip)
    result = os.popen(command).read()
    result = re.sub(r".*chunked", '',result,count=1, flags=re.DOTALL)
    devices = json.loads(result)
    db = sqlite3.connect('users.db')
    for switch_tuple in db.execute('SELECT * FROM users join customers on users.customer_id = customers.customer_id WHERE subscriber_id = ?', (subs_id,)):
        print switch_tuple
    #switch_tuple = db.fetchone()
    db.close()
    matched_devices = []
    if not switch_tuple:
        abort(404)
    for device in devices:
        if str(device['attachmentPoint'][0]['switchDPID']) == str(switch_tuple[3]):
            if str(device['attachmentPoint'][0]['port']) == str(switch_tuple[4]):
                add_device = device
                del add_device['attachmentPoint']
                del add_device['entityClass']
                del add_device['vlan']
                matched_devices.append(add_device) 
    return make_response(json.dumps(matched_devices))
    
################## USAGE ###############################
    
@app.route('/usage/<int:subs_id>', methods=['POST']) 
def set_usage_on_device(subs_id):   #adds flow to monitor usage on a device
    db = sqlite3.connect('users.db')
    c = db.cursor()
    #get switch id for customer in db
    c.execute('SELECT * FROM users join customers on users.customer_id = customers.customer_id WHERE subscriber_id = ?', (subs_id,))
    customer = c.fetchone()
    db.close()
    switch_id = customer[3]
    mac = request.json['mac']
    #pushing permanent flows onto switch
    command = "curl -d '{\"switch\":\"%s\", \"name\":\"%s-ul\", \"src-mac\":\"%s\", \"ether-type\":\"0x0800\", \"active\":\"true\", \"priority\":\"0\", \"actions\":\"output=normal\"}' http://%s:8080/wm/staticflowentrypusher/json" % (switch_id, mac, mac, controller_ip)
    result = os.popen(command).read()
    #print command                          
    command = "curl -d '{\"switch\":\"%s\", \"name\":\"%s-dl\", \"dst-mac\":\"%s\", \"ether-type\":\"0x0800\", \"active\":\"true\", \"priority\":\"0\", \"actions\":\"output=normal\"}' http://%s:8080/wm/staticflowentrypusher/json" % (switch_id, mac, mac, controller_ip)
    result = os.popen(command).read()
    #print result
    return result
    
@app.route('/usage/<int:subs_id>', methods=['DELETE'])
def delete_usage_on_device(subs_id): #deletes flow to monitor usage on a device
    mac = request.json['mac']
    command = "curl -X DELETE -d '{\"name\":\"%s-dl\"}' http://%s:8080/wm/staticflowentrypusher/json" % (mac, controller_ip)
    result = os.popen(command).read()
    command = "curl -X DELETE -d '{\"name\":\"%s-ul\"}' http://%s:8080/wm/staticflowentrypusher/json" % (mac, controller_ip)
    result = os.popen(command).read()
    return result
    
@app.route('/usage/<int:subs_id>', methods=['PUT']) 
def reset_usage_device(subs_id):   #resets flow byte counters for a device
    command = "curl http://%s:8080/wm/device/" % (controller_ip)
    result = os.popen(command).read()
    return result
    
@app.route('/usage/<int:subs_id>/<mac>', methods=['GET'])
def get_usage_device(subs_id, mac): #gets usage on a device
    db = sqlite3.connect('users.db')
    c = db.cursor()
    #get switch id for customer in db
    c.execute('SELECT * FROM users join customers on users.customer_id = customers.customer_id WHERE subscriber_id = ?', (subs_id,))
    customer = c.fetchone()
    db.close()
    switch_id = customer[3]
    command = "curl http://%s:8080/wm/core/switch/%s/flow/json" % (controller_ip, switch_id)
    result = os.popen(command).read()
    flows = json.loads(result)
    for flow in flows[switch_id]:
        if str(flow['match']['dataLayerDestination']) == str(mac):
            dl_usage = flow['byteCount']
        if str(flow['match']['dataLayerSource']) == str(mac):
            ul_usage = flow['byteCount']
    usage = {
            'download': dl_usage,
            'upload': ul_usage
    }
    return make_response(jsonify({'usage': usage}), 200)
    
@app.route('/usage/limit/<int:subs_id>', methods=['GET']) 
def get_limit(subs_id):   #get flow byte counter overflow limit
    return make_response(jsonify({'limit':32}), 200)
 
################# ERROR HANDLING ##############################
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

################ RUN TIME ####################################
if __name__ == '__main__':
    app.run(debug=True)
    #app.run(host='0.0.0.0')
