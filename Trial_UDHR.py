# -*- coding: utf-8 -*-
"""
Created on Sat Dec 21 14:02:28 2019

@author: Srivallabh
"""

# Module 2 - Create a Cryptocurrency

# To be installed:
# Flask==0.12.2: pip install Flask==0.12.2
# Postman HTTP Client: https://www.getpostman.com/
# requests==2.18.4: pip install requests==2.18.4

# Importing the libraries
import datetime
import hashlib
import json
from flask import Flask, jsonify, request, render_template
import requests
from uuid import uuid4
from urllib.parse import urlparse
from passlib.hash import bcrypt
# Part 1 - Building a Blockchain

class Blockchain:

    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_block(proof = 1, previous_hash = '0')
        self.nodes = set()
    
    def create_block(self, proof, previous_hash):
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash,
                 'Information': self.transactions}
        self.transactions = []
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof
    
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    
    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] != '00':
                return False
            previous_block = block
            block_index += 1
        return True
    
    
    def add_transaction(self,doctor,patient,date_of_birth,blood_group,birth_place,city,uid,user_type,gender,password,report,summ):
        self.transactions.append({'Doctor': doctor,
                                  'Patient': patient,
                                  'Date Of Birth': date_of_birth,
                                  'Blood Group':  blood_group,
                                  'Birth Place': birth_place,
                                  'City':  city,
                                  'Aadhar Number': uid,
                                  'Type':  user_type,
                                  'Gender' : gender,
                                  'Password' : password,
                                  'Report': report,
                                  'Summarized':summ
                                  })
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1
    
    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
    
    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False

# Part 2 - Mining our Blockchain

# Creating a Web App
app = Flask(__name__,template_folder='templates')

# Creating an address for the node on Port 5003
node_address = str(uuid4()).replace('-', '')

# Creating a Blockchain
blockchain = Blockchain()
@app.route('/sign_up')
def index():
    return render_template('signup.html')

@app.route('/prescription')
def pres():
    return render_template('prescription.html')

# Mining a new block
@app.route('/mine_block', methods = ['GET'])
def mine_block():
    previous_block= blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)

    
    #blockchain.add_transaction();
    #blockchain.add_transaction(doctor = node_address, patient = name,date_of_birth='08/12/1998',blood_group='B+',birth_place='Goa',city='Indore',uid=120,user_type='Legend',gender='Male', report=readable_hash,summ=hash_gen)
    #blockchain.add_transaction('Dr. Ayush Tejwani',request.form['name'], request.form['date_of_birth'],request.form['blood_group'],request.form['birth_place'],request.form['city'],request.form['uid'],request.form['user_type'],request.form['gender'])
    
    block = blockchain.create_block(proof, previous_hash)
    response = {'message': 'Congratulations, you just mined a block!',
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash']}
    return jsonify(response), 200

# Getting the full Blockchain
@app.route('/get_chain', methods = ['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

# Checking if the Blockchain is valid
@app.route('/is_valid', methods = ['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'message': 'All good. The Blockchain is valid.'}
    else:
        response = {'message': 'Houston, we have a problem. The Blockchain is not valid.'}
    return jsonify(response), 200

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/get_login', methods=['POST','GET'])
def get_login():
    if request.method == 'POST':
        uid = request.form['uid']
        date_of_birth = request.form['date_of_birth']
        print(uid)
        print(date_of_birth)
        #Create a function and then pass uid as argument to it
    check=blockchain.get_previous_block()
    new=check['Information']
    if(new[0]['Aadhar Number']==uid):
         
        response = {'Aadhar Numer':new[0]['Aadhar Number'] ,
                    'Name of User': new[0]['Patient'],
                                  'Blood Group': new[0]['Blood Group'],
                                  'Birth Place': new[0]['Birth Place'],
                                  'City': new[0]['City'],
                                  'Type':new[0]['Type'],
                                  'Gender':new[0]['Gender'],
                    
                'length': len(blockchain.chain)}
        return jsonify(response), 200
    response = {'message': 'Login done right'}
    return jsonify(response),200


# Adding a new transaction to the Blockchain
@app.route('/add_user_info', methods = ['POST'])
def add_transaction():
    #json = request.get_json()
    name = request.form['name']
    city = request.form['city']
    date_of_birth = request.form['date_of_birth']
    blood_group = request.form['blood_group']
    uid = request.form['uid']
    print("Hello")
    print(uid)
    print(name)
    print(city)
    print(date_of_birth)
    print(blood_group)
    user_type = request.form['user_type']
    print(user_type)
    birth_place = request.form['birth_place']
    print(birth_place)

    gender = request.form['gender']
    password = request.form['password']
    print(gender)
    print(password)
    h = bcrypt.hash(password)
    print(h)
    
    #output = name + city
    with open('ayush.docx',"rb") as f:
        bytes = f.read() # read entire file as bytes
    readable_hash = hashlib.sha256(bytes).hexdigest();
    with open('summarized.docx',"rb") as f:
        bytes1 = f.read() # read entire file as bytes
    hash_gen = hashlib.sha256(bytes1).hexdigest();

    #transaction_keys = ['doctor', 'patient', 'report']
    #user_data_key = ['doctor','name','date_of_birth', 'blood_group','birth_place','city','uid','user_type','gender']
    #if not all(key in json for key in user_data_key):
        #return 'Some elements of the transaction are missing', 400
    #add_transaction(self,doctor,patient,date_of_birth,blood_group,birth_place,city,uid,user_type,gender,report,summ):
    index = blockchain.add_transaction('Dr. Ayush Tejwani',name, date_of_birth,blood_group,birth_place,city,uid,user_type,gender,h,readable_hash,hash_gen)
    response = {'message': f'This transaction will be added to Block {index}'}
    return jsonify(response), 201

# Part 3 - Decentralizing our Blockchain

# Connecting new nodes
@app.route('/connect_node', methods = ['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return "No node", 400
    for node in nodes:
        blockchain.add_node(node)
    response = {'message': 'All the nodes are now connected. The Blockchain now contains the following nodes:',
                'total_nodes': list(blockchain.nodes)}
    return jsonify(response), 201

# Replacing the chain by the longest chain if needed
@app.route('/replace_chain', methods = ['GET'])
def replace_chain():
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response = {'message': 'The nodes had different chains so the chain was replaced by the longest one.',
                    'new_chain': blockchain.chain}
    else:
        response = {'message': 'All good. The chain is the largest one.',
                    'actual_chain': blockchain.chain}
    return jsonify(response), 200

# Running the app
app.run(host = '127.0.0.1', port = 5001)
