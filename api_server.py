from flask import Flask, request, jsonify, abort
import logging
import json
import os
from werkzeug.utils import secure_filename
from urllib.parse import unquote
from pymongo import MongoClient
from bson import ObjectId
from bson import json_util
from datetime import datetime
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
from datetime import timedelta
from flask_jwt_extended.exceptions import JWTExtendedException
from jwt import ExpiredSignatureError
from threading import Thread
from time import sleep
from functools import wraps

app = Flask(__name__)
# Create a logger
logger = logging.getLogger('api_server')
logger.setLevel(logging.DEBUG)  # Set the log level for the logger

# Create a file handler that logs debug and higher level messages
fh = logging.FileHandler('api_server.log')
fh.setLevel(logging.DEBUG)  # You can adjust the level if you want

# Create a formatter and set it for the handler
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(fh)

def read_list(file_path):
    """Reads the IP blacklist from a file."""
    try:
        with open(file_path, "r") as f:
            ips = set(line.strip() for line in f if line.strip())
        return ips
    except FileNotFoundError:
        return set()
    
SECRET = os.getenv("secret")
BACKEND_SECRET = os.getenv("backend_secret")
ALLOWED_IPS = read_list("/ip-lists/whitelist.txt")
blacklist = read_list("/ip-lists/blacklist.txt")
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
# Initialize JWT Manager
jwt = JWTManager(app)

def refresh_blacklist():
    global blacklist
    while True:
        blacklist = read_list("/ip-lists/blacklist.txt")
        sleep(60)  # Refresh every 60 seconds

class BlacklistMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        remote_addr = environ.get("REMOTE_ADDR")

        # Check if the IP address is in the blacklist
        if remote_addr in blacklist:
            return self.forbidden_response(start_response)

        return self.app(environ, start_response)

    def forbidden_response(self, start_response):
        start_response("403 Forbidden", [("Content-Type", "text/plain")])
        return [b"Forbidden"]

def add_to_blacklist(ip, file_path="blacklist.txt"):
    """Adds an IP address to the blacklist file."""
    with open(file_path, "a") as f:
        f.write(ip + "\n")
    blacklist.add(ip)

# Custom middleware to log and blacklist non-existent routes
class HoneypotMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        path_info = environ.get("PATH_INFO")
        remote_addr = environ.get("REMOTE_ADDR")

        # Check if this is a non-existent route
        with app.test_request_context(path_info):
            if app.view_functions.get(request.endpoint) is None:
                # Log and blacklist
                print(f"Honeypot triggered by IP: {remote_addr} at path: {path_info}")
                add_to_blacklist(remote_addr)

                # Return a mock admin username and password
                return self.mock_credentials_response(start_response)

        return self.app(environ, start_response)

    def mock_credentials_response(self, start_response):
        response = jsonify({"username": "admin", "password": "password123"})
        response.status_code = 200
        headers = [(k, v) for k, v in response.headers.items()]

        start_response("505 ERROR", headers)
        return [response.data]
    
# Custom JSON Encoder class
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            # Convert datetime objects to string
            return obj.isoformat()
        elif isinstance(obj, ObjectId):
            # Convert ObjectId objects to string (if using MongoDB ObjectIds)
            return str(obj)
        return json.JSONEncoder.default(self, obj)

def ip_whitelist(allowed_ips=ALLOWED_IPS):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.remote_addr not in allowed_ips:
                logger.warning(f"Unauthorized access attempt from IP: {request.remote_addr}")
                abort(403)  # Forbidden access
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Helper function to verify username and password
def verify_credentials(username, password):
    # Retrieve the hashed password from the environment variable with the username as the key
    stored_hashed_password = os.getenv(username)

    if not stored_hashed_password:
        # Username not found
        return False

    # Check if the provided password matches the stored hashed password
    if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
        return True
    
    return False

class LoggingMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # Extracting information from 'environ'
        request_method = environ.get('REQUEST_METHOD')
        path_info = environ.get('PATH_INFO')
        remote_addr = environ.get('REMOTE_ADDR')

        # Log the attempt
        logger.info(f"Connection attempt: Method: {request_method}, Path: {path_info}, IP: {remote_addr}")

        return self.app(environ, start_response)

def retrieve_key_from_document(collection_name, unique_key, unique_value, target_key, database):
    """
    Retrieve a specific key from a document in a MongoDB collection.
    :param collection_name: The name of the collection.
    :param unique_key: The key used for identifying the unique document.
    :param unique_value: The value of the unique key.
    :param target_key: The key to retrieve from the document.
    :return: The value of the target key, or None if not found.
    """
    client = MongoClient("mongodb://localhost:27017/")
    db = client[database]
    collection = db[collection_name]

    # Adjust the query based on whether the unique identifier is an ObjectId or not
    if unique_key == "_id":
        unique_value = ObjectId(unique_value)

    query = {unique_key: unique_value}
    document = collection.find_one(query, {target_key: 1, '_id': 0})

    if document:
        return document.get(target_key)
    else:
        return None

def retrieve_key_list(collection_name, unique_key, database):
    client = MongoClient('mongodb://localhost:27017/')  # Connect to MongoDB
    db = client[database]  # Connect to the database
    collection = db[collection_name]  # Connect to the collection

    list = []
    for document in collection.find():  # Iterate over all documents
        if unique_key in document:  # Check if 'subforum_link' key exists
            list.append(document[unique_key])  # Add the value to the list

    return list

def find_one_document(query, collection_name, database):
    client = MongoClient('mongodb://localhost:27017/')  # Connect to MongoDB
    db = client[database]  # Connect to the database
    collection = db[collection_name]  # Connect to the collection
    # If the query is based on '_id' and is a string, convert it to ObjectId
    if '_id' in query and isinstance(query['_id'], str):
        query['_id'] = ObjectId(query['_id'])

    return collection.find_one(query)



def insert_into_mongo(data_list, database, collection_db, unique_identifier, second_unique_identifier=None):
    try:
        if isinstance(data_list, str):
            # If data_list is a string, parse it as JSON
            data_list = json.loads(data_list)

        if isinstance(data_list, dict):
            data_list = [data_list]  # Wrap the dictionary in a list

        client = MongoClient("mongodb://localhost:27017/")
        db = client[database]
        collection = db[f"{collection_db}"]

        # Create index based on the presence of a second unique identifier
        if second_unique_identifier:
            collection.create_index([(f"{unique_identifier}", 1), (f"{second_unique_identifier}", 1)], unique=True)
        else:
            collection.create_index([(f"{unique_identifier}", 1)], unique=True)

        for data in data_list:
            # Construct query based on the provided unique identifiers
            if second_unique_identifier:
                query = {f"{unique_identifier}": data[f"{unique_identifier}"],
                         f"{second_unique_identifier}": data[f"{second_unique_identifier}"]}
            else:
                query = {f"{unique_identifier}": data[f"{unique_identifier}"]}

            update = {"$set": data}
            collection.update_one(query, update, upsert=True)

        logger.info("Data updated/inserted successfully into MongoDB.")
        return True
    except Exception as e:
        logger.error(f"Failed to update/insert data into MongoDB. Error: {e}")
        return False

def convert_if_numeric(s):
    if s.isdigit():
        return int(s)
    else:
        return s
    
def extract_collection(database_name, collection_name):
    # Connect to MongoDB
    client = MongoClient('mongodb://localhost:27017/')  # Replace with your MongoDB connection string

    # Access the specified database and collection
    db = client[database_name]
    collection = db[collection_name]

    # Retrieve all documents from the collection
    documents = list(collection.find())

    # Remove the "_id" field from each document
    for document in documents:
        document.pop('_id', None)

    
    # Convert the list of documents to a JSON string
    document_json = json.dumps(documents, cls=CustomJSONEncoder)

    return document_json

@app.errorhandler(JWTExtendedException)
def handle_expired_error(e):
    if isinstance(e, ExpiredSignatureError):
        return jsonify({"msg": "Token has expired"}), 401
    # Handle other JWT exceptions
    return jsonify({"msg": "JWT error: " + str(e)}), 500

# Route for authentication
@app.route('/request_token', methods=['POST'])
@ip_whitelist()
def login():
    logger.info(f"Received request from {request.remote_addr} to {request.path} with method {request.method}")
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    api_secret = request.headers.get('X-Secret')
    
    if api_secret != SECRET and api_secret != BACKEND_SECRET:
        return jsonify({"msg": "Unauthorized"}), 401

    
    if verify_credentials(username, password):
        access_token = create_access_token(identity=username, expires_delta=timedelta(hours=1))
        logger.info(f"User {username} from IP {request.remote_addr} successfully logged in")
        return jsonify(access_token=access_token), 200
    else:
        logger.error(f"User: {username} from IP {request.remote_addr} failed to log in")
        return jsonify({"msg": "Unauthorized"}), 401

@app.route('/api/collection', methods=['GET'])
@ip_whitelist()
@jwt_required()
def retrieve_collection():
    logger.info(f"Received request from {request.remote_addr} to {request.path} with method {request.method}")
    db_name = request.headers.get('X-Database')
    collection_name = request.headers.get('X-Collection')
    api_secret = request.headers.get('X-Secret')
    
    if api_secret != SECRET and api_secret != BACKEND_SECRET:
        return jsonify({"msg": "Unauthorized"}), 401

    
    if not all([collection_name, db_name]):
        return jsonify(error="Bad request"), 400

    try:
        collection_data = extract_collection(db_name, collection_name)
        return collection_data, 200
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return jsonify(error="An error occurred while retrieving the collection"), 500
    
@app.route('/find_one_document', methods=['GET'])
@ip_whitelist()
@jwt_required()
def retrieve_one_document():
    logger.info(f"Received request from {request.remote_addr} to {request.path} with method {request.method}")
    db_name = request.headers.get('X-Database')
    collection_name = request.headers.get('X-Collection')
    key_value = request.headers.get('X-Key')
    key = convert_if_numeric(key_value)
    value = request.headers.get('X-Value')
    is_url = request.headers.get('X-Is-URL')
    api_secret = request.headers.get('X-Secret')
    
    if api_secret != SECRET:
        return jsonify({"msg": "Unauthorized"}), 401
    if is_url == 'True':
        value = unquote(value)
    if not all([collection_name, key, value, db_name]):
        return jsonify(error="Bad request"), 400
    logger.info(f"{key}")
    logger.info(f"{value}")
    query = {key: value}
    try:
                
        existing_document = find_one_document(query, collection_name, db_name)
        if existing_document is not None:
            logger.info("Document retrieved successfully")
            serializable_document = json.loads(json_util.dumps(existing_document))
            return jsonify({'document': serializable_document}), 200
            

        else:
            logger.info("Document not found")
            return jsonify(error="Document not found"), 404
        
    except Exception as e:
        logger.error(f"Error while retrieving document: {e}")
        return jsonify(error="Internal server error"), 500


@app.route('/retrieve_key_list', methods=['GET'])
@ip_whitelist()
@jwt_required()
def retrieve_list():
    logger.info(f"Received request from {request.remote_addr} to {request.path} with method {request.method}")
    db_name = request.headers.get('X-Database')
    collection_name = request.headers.get('X-Collection')
    unique_key = request.headers.get('X-Unique-Key')
    api_secret = request.headers.get('X-Secret')
    
    if api_secret != SECRET:
        return jsonify({"msg": "Unauthorized"}), 401
    if not all([collection_name, unique_key, db_name]):
        return jsonify(error="Bad request"), 400
    
    try:
        list = retrieve_key_list(collection_name, unique_key, db_name)
        if list is not None:
            logger.info("List retrieved successfully")
            return jsonify({'list': list}), 200
        else:
            logger.info("List not found")
            return jsonify(error="List not found"), 404

    except Exception as e:
        logger.error(f"Error while retrieving list: {e}")
        return jsonify(error="Internal server error"), 500

@app.route('/retrieve_key_from_document', methods=['GET'])
@ip_whitelist()
@jwt_required()
def retrieve_key():
    logger.info(f"Received request from {request.remote_addr} to {request.path} with method {request.method}")
    db_name = request.headers.get('X-Database')
    collection_name = request.headers.get('X-Collection')
    unique_key = request.headers.get('X-Unique-Key')
    unique_value = request.headers.get('X-Unique-Value')
    target_key = request.headers.get('X-Target-Key')
    api_secret = request.headers.get('X-Secret')
    
    if api_secret != SECRET:
        return jsonify({"msg": "Unauthorized"}), 401
    
    if not all([collection_name, unique_key, unique_value, target_key, db_name]):
        return jsonify(error="Bad request"), 400

    try:
        key_to_return = retrieve_key_from_document(collection_name, unique_key, unique_value, target_key, db_name)

        if key_to_return is not None:
            logger.info("Key retrieved successfully")
            return jsonify({"target_key": key_to_return}), 200
        else:
            logger.info("Key not found")
            return jsonify(error="Key not found"), 404

    except Exception as e:
        logger.error(f"Error while retrieving key: {e}")
        return jsonify(error="Internal server error"), 500


@app.route('/insert', methods=['POST'])
@ip_whitelist()
@jwt_required()
# @ip_whitelist([ip_white_list])  # Replace with your allowed IP addresses
def insert_data():
    logger.info(f"Received request from {request.remote_addr} to {request.path} with method {request.method}")
    # Extract database and collection from headers
    db_name = request.headers.get('X-Database')
    logger.info(db_name)
    collection_name = request.headers.get('X-Collection')
    logger.info(collection_name)
    unique_identifier = request.headers.get('X-Unique-Identifier')
    logger.info(unique_identifier)
    second_unique_identifier = request.headers.get('X-Second-Unique-Identifier')
    logger.info(second_unique_identifier)
    api_secret = request.headers.get('X-Secret')
    
    if api_secret != SECRET:
        return jsonify({"msg": "Unauthorized"}), 401
    
    if not db_name or not collection_name or not unique_identifier:
        return "Bad request", 400

    data = request.json
    success = insert_into_mongo(data, db_name, collection_name, unique_identifier, second_unique_identifier)

    if success:
        logger.info("Data successfully updated/inserted into MongoDB.")
        return "Data updated/inserted successfully", 200
    else:
        logger.error("Failed to update/insert data into MongoDB.")
        return "Failed to update/insert data", 500

@app.route('/upload', methods=['POST'])
@ip_whitelist()
@jwt_required()
def upload_file():
    api_secret = request.headers.get('X-Secret')
    
    if api_secret != SECRET:
        return jsonify({"msg": "Unauthorized"}), 401
    
    if 'file' in request.files:
        file = request.files['file']
        filename = secure_filename(file.filename)
        file_path = f"assets/tg_scrapers"
        save_path = os.path.join(file_path, filename)
        file.save(save_path)
        
        # Return the file URL or path
        return jsonify({'message': 'File uploaded successfully', 'file_path': save_path}), 200
    return jsonify({'message': 'Bad request'}), 400

# Screenshot testing:
UPLOAD_FOLDER = 'assets/forum_scrappers'
ALLOWED_EXTENSIONS = {'png'}
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_images', methods=['POST'])
@ip_whitelist()
@jwt_required()
def upload_images():
    api_secret = request.headers.get('X-Secret')
    folder_request = request.headers.get('X-Folder')
    if api_secret != SECRET:
        return jsonify({"msg": "Unauthorized"}), 401
    
    if 'files' not in request.files:
        return jsonify({'message': 'Bad request'}), 400

    files = request.files.getlist('files')
    for file in files:
        if file.filename == '':
            return jsonify({'message': 'Bad request'}), 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            if folder_request is None:
                folder = UPLOAD_FOLDER
            
            folder = f"{UPLOAD_FOLDER}/{folder_request}"
            file.save(os.path.join(folder, filename))
        else:
            return jsonify({'message': 'Bad request'}), 400

    return jsonify({'message': 'Files successfully uploaded'}), 200

if __name__ == '__main__':
    # Set up the logging middleware first
    app.wsgi_app = LoggingMiddleware(app.wsgi_app)
    # # Set up the blacklist middleware on top
    # app.wsgi_app = BlacklistMiddleware(app.wsgi_app)
    # Start the blacklist refresh thread
    Thread(target=refresh_blacklist).start()
    # Set up middleware chain
    app.wsgi_app = BlacklistMiddleware(HoneypotMiddleware(app.wsgi_app))
    # Start the server
    app.run(ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=5000)