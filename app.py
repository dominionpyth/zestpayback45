import firebase_admin
from firebase_admin import credentials





import os
# import firebase_admin

from flask import Flask
# app.py
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth, firestore
import os
from datetime import datetime, timedelta
import json

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize Firebase Admin SDK
# Make sure to replace with your own service account key
try:
    # Try to get the service account key from environment variable first
    service_account_key = os.environ.get('FIREBASE_SERVICE_ACCOUNT_KEY')
    if service_account_key:
        cred = credentials.Certificate(json.loads(service_account_key))
    else:
        # Fallback to a file if environment variable is not set
        cred = credentials.Certificate('serviceAccountKey.json')
    
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    print("Firebase Admin SDK initialized successfully")
except Exception as e:
    print(f"Error initializing Firebase Admin SDK: {e}")

# API Routes
@app.route('/api/login', methods=['POST'])
def login():
    try:
        # Get email and password from request
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        # Validate input
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400
        
        # Authenticate user with Firebase
        try:
            # Sign in user with email and password
            user = auth.get_user_by_email(email)
            
            # Note: Firebase Admin SDK doesn't directly support password verification
            # You would need to use Firebase REST API for this
            # For this example, we'll assume the password is verified through a custom token
            
            # Check if email is verified
            if not user.email_verified:
                return jsonify({
                    'success': False, 
                    'message': 'Email not verified',
                    'emailVerified': False,
                    'uid': user.uid
                }), 403
            
            # Create custom token for client-side authentication
            custom_token = auth.create_custom_token(user.uid)
            
            # Record login in Firestore
            record_user_login(user.uid, email, request.remote_addr)
            
            # Return success response with custom token
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'token': custom_token.decode('utf-8'),
                'emailVerified': True,
                'uid': user.uid
            }), 200
            
        except auth.UserNotFoundError:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        except Exception as e:
            return jsonify({'success': False, 'message': f'Authentication error: {str(e)}'}), 401
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/verify-password', methods=['POST'])
def verify_password():
    """
    This endpoint uses Firebase REST API to verify password
    since Firebase Admin SDK doesn't directly support password verification
    """
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        # Firebase Web API key (should be stored securely)
        # In production, this should be stored in environment variables
        firebase_api_key = os.environ.get('FIREBASE_API_KEY', 'YOUR_FIREBASE_API_KEY')
        
        # Make request to Firebase REST API
        import requests
        
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={firebase_api_key}"
        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        
        response = requests.post(url, json=payload)
        response_data = response.json()
        
        if response.status_code == 200:
            # Password is correct
            return jsonify({
                'success': True,
                'message': 'Password verified',
                'idToken': response_data.get('idToken'),
                'localId': response_data.get('localId')
            }), 200
        else:
            # Password is incorrect or other error
            error_message = response_data.get('error', {}).get('message', 'Authentication failed')
            return jsonify({
                'success': False,
                'message': error_message
            }), 401
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/resend-verification', methods=['POST'])
def resend_verification():
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400
        
        try:
            # Get user by email
            user = auth.get_user_by_email(email)
            
            # Generate email verification link
            link = auth.generate_email_verification_link(email)
            
            # In a real application, you would send this link via email
            # For this example, we'll just return it
            return jsonify({
                'success': True,
                'message': 'Verification email sent',
                'verificationLink': link
            }), 200
            
        except auth.UserNotFoundError:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        except Exception as e:
            return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

def record_user_login(user_id, email, ip_address):
    try:
        # Get user agent info
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Get current timestamp
        timestamp = datetime.now()
        
        # Store login data in Firestore
        login_data = {
            'userId': user_id,
            'email': email,
            'timestamp': timestamp,
            'ipAddress': ip_address,
            'userAgent': user_agent,
            'loginStatus': 'success'
        }
        
        # Add to userLogins collection
        db.collection('userLogins').add(login_data)
        
        print("User login recorded successfully")
    except Exception as e:
        print(f"Error recording user login: {e}")



if __name__ == "__main__":
  app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 3000)))