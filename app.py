#!flask/bin/python
from flask import Flask, jsonify, g, abort, make_response, request
from flask.ext.httpauth import HTTPBasicAuth
from flask.ext.sqlalchemy import SQLAlchemy
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
import argparse, time
import os
import json
import re
import sqlite3

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:openflow@localhost/isp'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SECRET_KEY'] = 'some secret key for hashing'

db = SQLAlchemy(app)
auth = HTTPBasicAuth()

controller_ip = '149.171.189.1'     #IP address of SDN controller

class User(db.Model):
    __tablename__ = 'users'
    handle = db.Column(db.String(30), primary_key=True)
    customer_id = db.Column(db.String(30), db.ForeignKey('customers.customer_id'))

class Customer(db.Model):
    __tablename__ = 'customers'
    customer_id = db.Column(db.String(30), primary_key=True)
    switch_id = db.Column(db.String(30))
    port = db.Column(db.String(3))
    billingDay = db.Column(db.Integer)
    quota = db.Column(db.Integer)
    rel = db.relationship('User', uselist=False, backref='customers', foreign_keys="User.customer_id")
    

class SMP(db.Model):
    __tablename__ = 'smp'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(120))
    
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
def verify_password(username_or_token, password):
    smp = SMP.verify_auth_token(username_or_token)
    if not smp:
        #try to authenticate with username/password
        smp = SMP.query.filter_by(username=username_or_token).first()
        if not smp or not smp.verify_password(password):
            return False
    g.smp = smp
    return True


 ############### SMP AUTHENTICATION #############################   
@app.route('/residence/isp/api/v1.0/smp/register', methods=['POST'])
def register_smp():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400) #missing arguments
    if SMP.query.filter_by(username=username).first() is not None:
        abort(400)
    user = SMP(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'username':user.username}), 201

@app.route('/residence/isp/api/v1.0/smp/token', methods=['GET'])
@auth.login_required
def get_auth_token():
    token = g.smp.generate_auth_token()
    return jsonify({'token':token.decode('ascii')})

################ FIREWALL ##################################### 
@app.route('/residence/isp/api/v1.0/block/<handle>', methods=['POST']) 
def set_block_on_device(handle):   #adds flow to monitor usage on a device
    #get switch id for customer in db
    db_entry = User.query.filter_by(handle=handle).\
                   join(Customer, User.customer_id==Customer.customer_id).\
                   add_columns(User.handle, Customer.switch_id).\
                   first()
    switch_id = db_entry.switch_id
    mac = request.json['mac']
    #pushing permanent flows onto switch
    command = "curl -d '{\"switch\":\"%s\", \"name\":\"%s-blockul\", \"src-mac\":\"%s\", \"active\":\"true\", \"priority\":\"0\"}' http://%s:8080/wm/staticflowentrypusher/json" % (switch_id, mac, mac, controller_ip)
    result = os.popen(command).read()
    #print command                          
    command = "curl -d '{\"switch\":\"%s\", \"name\":\"%s-blockdl\", \"dst-mac\":\"%s\", \"active\":\"true\", \"priority\":\"0\"}' http://%s:8080/wm/staticflowentrypusher/json" % (switch_id, mac, mac, controller_ip)
    result = os.popen(command).read()
    #print result
    return result

@app.route('/residence/isp/api/v1.0/block', methods=['DELETE'])
def delete_block_on_device(): #deletes flow to monitor usage on a device
    mac = request.json['mac']
    command = "curl -X DELETE -d '{\"name\":\"%s-blockdl\"}' http://%s:8080/wm/staticflowentrypusher/json" % (mac, controller_ip)
    result = os.popen(command).read()
    command = "curl -X DELETE -d '{\"name\":\"%s-blockul\"}' http://%s:8080/wm/staticflowentrypusher/json" % (mac, controller_ip)
    result = os.popen(command).read()
    return result

################ SUBSCRIBER REGISTRATION ######################
@app.route('/residence/isp/api/v1.0/register/<cust_id>', methods=['GET'])
#@auth.login_required
def check_cust_id(cust_id):
    customer = Customer.query.filter_by(customer_id=cust_id).first()
    if not customer:
        response = make_response(jsonify({'error':'No customer found'}), 400)
    else:
        customer_row = Customer.query.filter_by(customer_id=cust_id).\
                   outerjoin(User, User.customer_id==Customer.customer_id).\
                   add_columns(User.handle, Customer.billingDay, Customer.quota).\
                   first()
        if not customer_row.handle:     #if no handle created yet
            result = User.query.order_by(User.handle).all()
            if not result:      #if no users in the database yet
                number = 1
            else:
                last = result[-1]
                number = last.handle[-1]
                number = int(number) + 1
            handle = "albert_" + str(number)
            user = {
                'handle' : handle,
                'quota' : customer_row.quota,
                'billingDay' : customer_row.billingDay
            }
            user_entry = User(handle=handle,customer_id=cust_id)
            db.session.add(user_entry)
            db.session.commit()
            response = make_response(jsonify(user))
        else:
            response = make_response(jsonify({'error':'User already in database'}), 400)
    #response.headers['Connection'] = 'Keep-Alive'
    return response

############# DEVICE DISCOVERY ###########################
@app.route('/residence/isp/api/v1.0/devices/<handle>/', methods=['GET'])
def get_devices(handle):
    #command to get devices
    command = "curl http://%s:8080/wm/device/" % (controller_ip)
    result = os.popen(command).read()
    devices = json.loads(result)
    switch_tuple = User.query.filter_by(handle=handle).\
                   join(Customer, User.customer_id==Customer.customer_id).\
                   add_columns(User.handle, Customer.switch_id, Customer.port).\
                   first()
    matched_devices = []
    if not switch_tuple:
        abort(404)
    for device in devices:
        if not device ['attachmentPoint']:
            continue
        for switch in device['attachmentPoint']:
            if str(switch['switchDPID']) == str(switch_tuple.switch_id):
                if str(switch['port']) == str(switch_tuple.port):
                    add_device = device
                    del add_device['attachmentPoint']
                    del add_device['entityClass']
                    del add_device['vlan']
                    matched_devices.append(add_device) 
    return make_response(json.dumps(matched_devices))
    
################## USAGE ###############################   
@app.route('/residence/isp/api/v1.0/usage/<handle>', methods=['POST']) 
def set_usage_on_device(handle):   #adds flow to monitor usage on a device
    #get switch id for customer in db
    db_entry = User.query.filter_by(handle=handle).\
                   join(Customer, User.customer_id==Customer.customer_id).\
                   add_columns(User.handle, Customer.switch_id).\
                   first()
    switch_id = db_entry.switch_id
    mac = request.json['mac']
    #pushing permanent flows onto switch
    command = "curl -d '{\"switch\":\"%s\", \"name\":\"%s-ul\", \"src-mac\":\"%s\", \"ether-type\":\"0x0800\", \"active\":\"true\", \"priority\":\"1\", \"actions\":\"output=normal\"}' http://%s:8080/wm/staticflowentrypusher/json" % (switch_id, mac, mac, controller_ip)
    result = os.popen(command).read()
    #print command                          
    command = "curl -d '{\"switch\":\"%s\", \"name\":\"%s-dl\", \"dst-mac\":\"%s\", \"ether-type\":\"0x0800\", \"active\":\"true\", \"priority\":\"1\", \"actions\":\"output=normal\"}' http://%s:8080/wm/staticflowentrypusher/json" % (switch_id, mac, mac, controller_ip)
    result = os.popen(command).read()
    #print result
    return result
    
@app.route('/residence/isp/api/v1.0/usage/', methods=['DELETE'])
def delete_usage_on_device(): #deletes flow to monitor usage on a device
    mac = request.json['mac']
    command = "curl -X DELETE -d '{\"name\":\"%s-dl\"}' http://%s:8080/wm/staticflowentrypusher/json" % (mac, controller_ip)
    result = os.popen(command).read()
    command = "curl -X DELETE -d '{\"name\":\"%s-ul\"}' http://%s:8080/wm/staticflowentrypusher/json" % (mac, controller_ip)
    result = os.popen(command).read()
    return result
    
@app.route('/residence/isp/api/v1.0/usage/<handle>/<mac>', methods=['GET'])
def get_usage_device(handle, mac): #gets usage on a device
    db_entry = User.query.filter_by(handle=handle).\
                   join(Customer, User.customer_id==Customer.customer_id).\
                   add_columns(User.handle, Customer.switch_id).\
                   first()
    switch_id = db_entry.switch_id
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
            'upload': ul_usage,
            'timestamp':time.time()
    }
    return make_response(jsonify({'usage': usage}), 200)

 ################ RUN TIME ####################################
if __name__ == '__main__':
    app.run(debug=True)
    #app.run(host='0.0.0.0')
    
################# ERROR HANDLING ##############################
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)
