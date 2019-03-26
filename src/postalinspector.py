"""
# Postal Inspector
Check an email file for malicious urls and attachments in VT, requires a VT private API key
Author: Cooper Quintin <cooperq@eff.org>
License: GPLv3
"""
import base64
import email
import hashlib
import json
import os
import sys
import datetime


import requests
from urlextract import URLExtract
from flask import Flask, request, abort
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///artifacts.db'
db = SQLAlchemy(app)
db.create_all()
vtapi = os.getenv("VT_API_KEY")

@app.route("/v1/message", methods=['POST'])
def handle_message():
    # extract eml from request
    content = request.json
    #print(content)
    if not "data" in content:
        abort(400)

    eml = email.message_from_bytes(base64.b64decode(content["data"]))

    responses = parse_eml(eml)
    return json.dumps(responses)


def parse_eml(eml):
    hashes = []
    urls = []
    responses = []

    for part in eml.walk():
        if part.get_content_disposition() != "attachment" and \
        part.get_content_type() == "text/plain" \
        or part.get_content_type == "text/html":
            text = str(part.get_payload(decode=True)).replace("\\n", " ")
            extractor = URLExtract()
            urls = list(set(extractor.find_urls(text)))


        if part.get_content_disposition() == "attachment":
            attach = base64.b64decode(part.get_payload())
            hashes.append(hashlib.sha256(attach).hexdigest())

    print(f"hashes: {hashes}")
    print(f"urls: {urls}")

    for shasum in hashes:
        artifact = Artifact.query.filter_by(handle = shasum).first()
        if(artifact):
            print(f"{shasum} already exists in DB")
            responses.append(artifact.response)
        else:
            params = {'apikey': vtapi, 'resource': shasum}
            headers = {
            "Accept-Encoding": "gzip, deflate"
            }
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
            params=params, headers=headers)
            json_response = response.json()

            artifact = Artifact(handle=shasum, response=json.dumps(json_response))
            db.session.add(artifact)
            db.session.commit()

            responses.append(json_response)

    for url in urls:
        artifact = Artifact.query.filter_by(handle = url).first()
        if(artifact):
            print(f"{url} already exists in DB")
            responses.append(artifact.response)
        else:

            headers = {
            "Accept-Encoding": "gzip, deflate",
            }
            params = {'apikey': vtapi, 'resource':url}
            response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
            params=params, headers=headers)
            json_response = response.json()

            artifact = Artifact(handle=url, response=json.dumps(json_response))
            db.session.add(artifact)
            db.session.commit()

            responses.append(json_response)

    return responses


def main():
    if vtapi is None:
        sys.exit("Virus total api key not found\nCreate an environment variable called VT_API_KEY")

    try:
        with open(sys.argv[1]) as f:
            eml = email.message_from_file(f)
    except (IndexError, FileNotFoundError) as e:
        sys.exit("""
        Postal Inspector - Inspect attachments and urls from an email in VT without uploading anything.

        Usage:
            postalinspector.py <path to eml file>
        """)

    responses = parse_eml(eml)
    print(responses)

class Artifact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    handle = db.Column(db.String(), unique=True, nullable=False)
    response = db.Column(db.Text(), nullable=False)
    last_update = db.Column(db.DateTime(), default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"<Artifact: {self.handle}>"

if __name__ == "__main__":
    main()
