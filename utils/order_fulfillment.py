import uuid
import logging
from datetime import datetime
from typing import List, Dict, Any

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_order_id(user_id: str) -> str:
    """Create unique order ID"""
    timestamp = int(datetime.now().timestamp())
    unique_id = str(uuid.uuid4())[:8]
    order_id = f"SH{user_id}_{timestamp}_{unique_id}"
    logger.info(f"Created order ID: {order_id}")
    return order_id

def check_stock_availability(items: List[Dict[str, Any]]) -> bool:
    """Check if all items are in stock"""
    try:
        # Import here to avoid circular imports
        import sys
        import os
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        # We'll check this in the main application instead
        logger.info(f"Checking stock for {len(items)} items")
        return True  # Will be properly checked in main.py
        
    except Exception as e:
        logger.error(f"Stock check failed: {e}")
        return False

def process_payment(order_id: str, payment_method: str, amount: float) -> Dict[str, Any]:
    """Process payment through selected gateway"""
    logger.info(f"Processing payment for order {order_id}: {payment_method}, ${amount}")
    
    if payment_method == 'paypal':
        try:
            from utils.paypal_client import PayPalClient
            
            paypal_client = PayPalClient()
            
            # Create PayPal payment
            payment_result = paypal_client.create_payment(
                amount=amount,
                return_url=f"http://localhost:5000/payment/success?order_id={order_id}",
                cancel_url=f"http://localhost:5000/payment/cancel?order_id={order_id}",
                description=f"StyleHub Pro Order {order_id}"
            )
            
            if payment_result:
                # Find approval URL
                approval_url = None
                for link in payment_result.get('links', []):
                    if link.get('rel') == 'approval_url':
                        approval_url = link.get('href')
                        break
                
                logger.info(f"PayPal payment created successfully: {payment_result.get('id')}")
                return {
                    'success': True,
                    'payment_id': payment_result.get('id'),
                    'approval_url': approval_url,
                    'status': 'created'
                }
            else:
                logger.error("Failed to create PayPal payment")
                return {
                    'success': False,
                    'error': 'Failed to create PayPal payment'
                }
                
        except Exception as e:
            logger.error(f"PayPal payment processing error: {e}")
            return {
                'success': False,
                'error': f'PayPal error: {str(e)}'
            }
    
    # For other payment methods, return mock success for now
    logger.info(f"Mock payment processed for {payment_method}")
    return {
        'success': True,
        'payment_id': f"demo_{payment_method}_{int(datetime.now().timestamp())}",
        'status': 'completed'
    }

def dispatch_order(order_id: str, items: List[Dict[str, Any]]) -> bool:
    """Dispatch order for shipping"""
    try:
        logger.info(f"Dispatching order {order_id} with {len(items)} items")
        
        # In a real implementation, this would:
        # 1. Update inventory
        # 2. Create shipping labels
        # 3. Notify warehouse
        # 4. Update order status
        
        logger.info(f"Order {order_id} dispatched successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to dispatch order {order_id}: {e}")
        return False

def send_order_confirmation(user_id: str, order_id: str) -> bool:
    """Send order confirmation email/SMS"""
    try:
        logger.info(f"Sending order confirmation for order {order_id} to user {user_id}")
        
        # In a real implementation, integrate with:
        # - Email service (SendGrid, AWS SES, etc.)
        # - SMS service (Twilio, AWS SNS, etc.)
        
        print(f"\n📧 ORDER CONFIRMATION SENT")
        print(f"Order ID: {order_id}")
        print(f"User ID: {user_id}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*50)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to send order confirmation: {e}")
        return False

def send_dispatch_notification(user_id: str, order_id: str) -> bool:
    """Send dispatch notification"""
    try:
        logger.info(f"Sending dispatch notification for order {order_id} to user {user_id}")
        
        print(f"\n🚚 DISPATCH NOTIFICATION SENT")
        print(f"Order ID: {order_id}")
        print(f"User ID: {user_id}")
        print(f"Status: Order is being prepared for shipping")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*50)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to send dispatch notification: {e}")
        return False

def update_inventory(items: List[Dict[str, Any]]) -> bool:
    """Update product inventory after successful payment"""
    try:
        logger.info(f"Updating inventory for {len(items)} items")
        
        # This will be handled in the main application
        # where we have access to the database models
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to update inventory: {e}")
        return False
