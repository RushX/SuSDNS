
#  * SuSDNS - Proprietary Software
#  * Copyright (c) 2024 Rushikesh Muley. All rights reserved.
#  *
#  * This file is part of SuSDNS. Unauthorized copying, modification, or distribution of this file,
#  * via any medium, is strictly prohibited without prior written permission from the author.
#  *
#  * For inquiries, contact: Rushikesh Muley (rushikeshmuley@outlook.com)

from flask import Flask, request, jsonify
import pickle
import numpy as np
import redis

# Initialize Flask app
app = Flask(__name__)

# Load resources and trained model
with open('resources.pkl', 'rb') as f:
    resources = pickle.load(f)

with open('random_forest_model.pkl', 'rb') as f:
    clf = pickle.load(f)

# Extract necessary resources from resources.pkl
alexa_counts = resources['alexa_counts']  # or whatever variable name it uses
dict_counts = resources['dict_counts']  # or whatever variable name it uses
alexa_vc = resources['alexa_vc']  # or whatever vectorizer name it uses
dict_vc = resources['dict_vc']  # or whatever vectorizer name it uses

# Initialize Redis connection
r = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)

# Define entropy function
def entropy(string):
    from collections import Counter
    import math
    probs = [float(string.count(c)) / len(string) for c in set(string)]
    return -sum(p * math.log(p, 2) for p in probs)

# Define the isDGA function
def isDGA(domain):
    # Check if the result is cached
    cached_result = r.get(domain)
    if cached_result:
        return cached_result

    # Calculate matches for Alexa and dictionary vectors
    _alexa_match = alexa_counts * alexa_vc.transform([domain]).T
    _dict_match = dict_counts * dict_vc.transform([domain]).T
    _alexa_match = _alexa_match.reshape(-1)
    _dict_match = _dict_match.reshape(-1)

    # Prepare feature array
    _X = np.array([len(domain), entropy(domain), *_alexa_match, *_dict_match], dtype=object).reshape(1, -1)
    result = clf.predict(_X)[0]

    # Cache result for future use (with expiry of 1 hour)
    r.set(domain, result, ex=3600)

    return result

# Define the /isDGA endpoint
@app.route('/isDGA', methods=['POST'])
def predict_dga():
    data = request.json
    domain = data.get('domain')

    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    try:
        # Call the isDGA function and return the result
        label = 'legit' if isDGA(domain) == "legit" else 'dga'
        return jsonify({'domain': domain, 'label': label})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/', methods=['GET'])
def dga_warning():
    # Extract the domain from query parameters
    # domain = request.args.get('domain', 'unknown')

    # Customize the warning response
    warning_message = {
        "status": "blocked",
        "message": "The requested domain has been identified as malicious (DGA).",
        # "domain": domain,
        "remediation": "If you believe this is a mistake, please contact your network administrator."
    }

    return jsonify(warning_message), 403  # HTTP 403 Forbidden status

# Run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)