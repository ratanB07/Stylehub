import os
import requests
import json
from datetime import datetime, timedelta
import logging

class PayPalClient:
    def __init__(self):
        # Use your real PayPal credentials
        self.client_id = os.environ.get('PAYPAL_CLIENT_ID', 'AbqT_zYxXaNzeO87tuPJ_BCRXih_3pvCC8iAAsCiulUNVDA-asM-XFNFvC3_d5vnXxCa55BP_VWFuYa2')
        self.client_secret = os.environ.get('PAYPAL_CLIENT_SECRET', 'EK9ydaWwuwTIZzkx59cXy9cov4C1m_4u4WbxffJO46m8KvDF8Pz-dtCWLHJ44eveoA37GqLTmezIcU_D')
        
        # Use sandbox for testing, live for production
        self.base_url = os.environ.get('PAYPAL_BASE_URL', 'https://api.sandbox.paypal.com')
        self.access_token = None
        self.token_expires_at = None
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def get_access_token(self):
        """Get PayPal access token"""
        if self.access_token and self.token_expires_at and datetime.now() < self.token_expires_at:
            return self.access_token
        
        url = f"{self.base_url}/v1/oauth2/token"
        headers = {
            'Accept': 'application/json',
            'Accept-Language': 'en_US',
        }
        data = 'grant_type=client_credentials'
        
        try:
            self.logger.info("Requesting PayPal access token...")
            response = requests.post(
                url, 
                headers=headers, 
                data=data, 
                auth=(self.client_id, self.client_secret),
                timeout=30
            )
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data['access_token']
            # Set expiration time (subtract 60 seconds for safety)
            expires_in = token_data.get('expires_in', 3600) - 60
            self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)
            
            self.logger.info("PayPal access token obtained successfully")
            return self.access_token
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"PayPal token request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response content: {e.response.text}")
            return None
    
    def create_payment(self, amount, currency='USD', return_url=None, cancel_url=None, description="StyleHub Pro Purchase"):
        """Create PayPal payment"""
        access_token = self.get_access_token()
        if not access_token:
            return None
        
        url = f"{self.base_url}/v1/payments/payment"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}',
        }
        
        payment_data = {
            "intent": "sale",
            "payer": {
                "payment_method": "paypal"
            },
            "transactions": [{
                "amount": {
                    "total": f"{amount:.2f}",
                    "currency": currency
                },
                "description": description,
                "item_list": {
                    "items": [{
                        "name": "StyleHub Pro Items",
                        "sku": "stylehub-items",
                        "price": f"{amount:.2f}",
                        "currency": currency,
                        "quantity": 1
                    }]
                }
            }],
            "redirect_urls": {
                "return_url": return_url or "http://localhost:5000/payment/success",
                "cancel_url": cancel_url or "http://localhost:5000/payment/cancel"
            }
        }
        
        try:
            self.logger.info(f"Creating PayPal payment for amount: {amount}")
            response = requests.post(url, headers=headers, json=payment_data, timeout=30)
            response.raise_for_status()
            
            payment_result = response.json()
            self.logger.info(f"PayPal payment created successfully: {payment_result.get('id')}")
            return payment_result
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"PayPal payment creation failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response content: {e.response.text}")
            return None
    
    def execute_payment(self, payment_id, payer_id):
        """Execute PayPal payment"""
        access_token = self.get_access_token()
        if not access_token:
            return None
        
        url = f"{self.base_url}/v1/payments/payment/{payment_id}/execute"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}',
        }
        
        execute_data = {
            "payer_id": payer_id
        }
        
        try:
            self.logger.info(f"Executing PayPal payment: {payment_id}")
            response = requests.post(url, headers=headers, json=execute_data, timeout=30)
            response.raise_for_status()
            
            execution_result = response.json()
            self.logger.info(f"PayPal payment executed successfully: {execution_result.get('state')}")
            return execution_result
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"PayPal payment execution failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response content: {e.response.text}")
            return None
    
    def get_payment_details(self, payment_id):
        """Get PayPal payment details"""
        access_token = self.get_access_token()
        if not access_token:
            return None
        
        url = f"{self.base_url}/v1/payments/payment/{payment_id}"
        headers = {
            'Authorization': f'Bearer {access_token}',
        }
        
        try:
            self.logger.info(f"Getting PayPal payment details: {payment_id}")
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            payment_details = response.json()
            self.logger.info(f"PayPal payment details retrieved successfully")
            return payment_details
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"PayPal payment details request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response content: {e.response.text}")
            return None

    def verify_webhook(self, headers, body, webhook_id):
        """Verify PayPal webhook signature"""
        access_token = self.get_access_token()
        if not access_token:
            return False
        
        url = f"{self.base_url}/v1/notifications/verify-webhook-signature"
        verify_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}',
        }
        
        verify_data = {
            "auth_algo": headers.get('PAYPAL-AUTH-ALGO'),
            "cert_id": headers.get('PAYPAL-CERT-ID'),
            "transmission_id": headers.get('PAYPAL-TRANSMISSION-ID'),
            "transmission_sig": headers.get('PAYPAL-TRANSMISSION-SIG'),
            "transmission_time": headers.get('PAYPAL-TRANSMISSION-TIME'),
            "webhook_id": webhook_id,
            "webhook_event": json.loads(body)
        }
        
        try:
            response = requests.post(url, headers=verify_headers, json=verify_data, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            return result.get('verification_status') == 'SUCCESS'
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"PayPal webhook verification failed: {e}")
            return False
