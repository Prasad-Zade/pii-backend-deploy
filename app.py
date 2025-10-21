from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
import json
from datetime import datetime

# Import the model wrapper and PII dependency handler
from model_wrapper import get_model_wrapper
from pii_dependency_handler import PIIDependencyHandler

app = Flask(__name__)
CORS(app)

# Initialize the model wrapper and PII dependency handler
model_wrapper = get_model_wrapper()
pii_handler = PIIDependencyHandler()
print(f"[INFO] Model Status: {model_wrapper.get_status()}")
print(f"[INFO] PII Dependency Handler initialized")

# In-memory storage for sessions (in production, use a database)
sessions = {}
messages = {}

@app.route('/', methods=['GET'])
def index():
    """Root endpoint"""
    return jsonify({
        'service': 'PII Privacy Handler API',
        'status': 'running',
        'endpoints': {
            'health': '/api/health',
            'sessions': '/api/sessions',
            'messages': '/api/sessions/<session_id>/messages'
        }
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    model_status = model_wrapper.get_status()
    return jsonify({
        'status': 'healthy',
        'privacy_handler_available': model_status['handler_available'],
        'amazonq_model_active': model_status['model_loaded'],
        'model_type': model_status['model_type'],
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/sessions', methods=['POST'])
def create_session():
    """Create a new chat session"""
    try:
        data = request.get_json() or {}
        session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(sessions)}"
        
        session = {
            'id': session_id,
            'title': data.get('title', 'New Chat'),
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        sessions[session_id] = session
        messages[session_id] = []
        
        return jsonify(session), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions', methods=['GET'])
def get_sessions():
    """Get all chat sessions"""
    try:
        return jsonify(list(sessions.values()))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions/<session_id>', methods=['DELETE'])
def delete_session(session_id):
    """Delete a chat session"""
    try:
        if session_id in sessions:
            del sessions[session_id]
            if session_id in messages:
                del messages[session_id]
            return jsonify({'message': 'Session deleted successfully'})
        else:
            return jsonify({'error': 'Session not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions/<session_id>/messages', methods=['GET', 'POST'])
def handle_messages(session_id):
    """Handle messages in a session"""
    try:
        # Auto-create session if it doesn't exist
        if session_id not in sessions:
            sessions[session_id] = {
                'id': session_id,
                'title': 'Auto-created Chat',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            messages[session_id] = []
        
        # Handle GET request
        if request.method == 'GET':
            return jsonify(messages.get(session_id, []))
        
        # Handle POST request
        data = request.get_json()
        if not data or 'text' not in data:
            return jsonify({'error': 'Text is required'}), 400
        
        user_text = data['text']
        start_time = datetime.now()
        
        # Check if PII analysis is provided from frontend
        pii_analysis = data.get('pii_analysis')
        
        # Process with PII dependency handler
        if pii_analysis:
            result = pii_handler.process_query(user_text, pii_analysis)
        else:
            result = pii_handler.process_query(user_text)
        
        message = {
            'id': f"msg_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(messages.get(session_id, []))}",
            'user_message': user_text,
            'anonymized_text': result.get('masked_query', user_text),
            'llm_prompt': result.get('masked_query', user_text),
            'llm_response_raw': result.get('llm_response', 'No response'),
            'llm_response_reconstructed': result.get('final_response', 'No response'),
            'bot_response': result.get('llm_response', 'No response'),
            'reconstructed_text': result.get('final_response', 'No response'),
            'privacy_score': _calculate_privacy_score(result),
            'processing_time': (datetime.now() - start_time).total_seconds(),
            'timestamp': datetime.now().isoformat(),
            'detected_entities': result.get('detected_entities', []),
            'entities_masked': result.get('entities_masked', []),
            'entities_preserved': result.get('entities_preserved', []),
            'context': result.get('context', 'General'),
            'privacy_preserved': result.get('privacy_preserved', False),
            'replacements': result.get('replacements', {}),
            'original_pii_map': result.get('original_pii_map', {})
        }
        
        # Store message
        if session_id not in messages:
            messages[session_id] = []
        messages[session_id].append(message)
        
        # Update session timestamp
        sessions[session_id]['updated_at'] = datetime.now().isoformat()
        
        return jsonify(message)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/clear-history', methods=['POST'])
def clear_history():
    """Clear all sessions and messages"""
    try:
        sessions.clear()
        messages.clear()
        return jsonify({'message': 'History cleared successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-pii', methods=['POST'])
def test_pii():
    """Test PII processing endpoint"""
    try:
        data = request.get_json()
        if not data or 'text' not in data:
            return jsonify({'error': 'Text is required'}), 400
        
        user_text = data['text']
        result = model_wrapper.process_query(user_text)
        
        return jsonify({
            'original': result.get('original_query', user_text),
            'masked': result.get('masked_query', user_text),
            'detected': result.get('detected_entities', []),
            'masked_entities': result.get('entities_masked', []),
            'preserved': result.get('entities_preserved', []),
            'replacements': result.get('replacements', {}),
            'response': result.get('final_response', 'No response'),
            'model_type': model_wrapper.get_status()['model_type']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def _calculate_privacy_score(result):
    """Calculate privacy score based on processing result"""
    if not result:
        return 50.0
    
    detected_count = len(result.get('detected_entities', []))
    masked_count = len(result.get('entities_masked', []))
    
    if detected_count == 0:
        return 100.0
    
    # Higher score for more entities masked
    masking_ratio = masked_count / detected_count if detected_count > 0 else 1.0
    base_score = 100.0 - (detected_count * 8)  # Reduce score for detected PII
    privacy_bonus = masking_ratio * 15  # Bonus for masking
    
    return max(20.0, min(100.0, base_score + privacy_bonus))

def _create_fallback_message(user_text, start_time):
    """Create a fallback message when privacy handler is not available"""
    import re
    
    # Simple PII detection patterns
    pii_patterns = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\b\d{3}-\d{3}-\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b'
    }
    
    detected_entities = []
    anonymized_text = user_text
    
    for entity_type, pattern in pii_patterns.items():
        if re.search(pattern, user_text):
            detected_entities.append(entity_type)
            anonymized_text = re.sub(pattern, f'[{entity_type.upper()}]', anonymized_text)
    
    return {
        'id': f"msg_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(messages)}",
        'user_message': user_text,
        'anonymized_text': anonymized_text,
        'bot_response': 'I understand your message. Your privacy is protected with basic anonymization.',
        'reconstructed_text': user_text,
        'privacy_score': 100.0 - (len(detected_entities) * 15),
        'processing_time': (datetime.now() - start_time).total_seconds(),
        'timestamp': datetime.now().isoformat(),
        'detected_entities': detected_entities,
        'entities_masked': detected_entities,
        'entities_preserved': [],
        'context': 'General',
        'privacy_preserved': len(detected_entities) > 0
    }

if __name__ == '__main__':
    print("[STARTUP] Starting PII Privacy Handler Backend...")
    model_status = model_wrapper.get_status()
    print(f"[INFO] Privacy Handler Available: {model_status['handler_available']}")
    print(f"[INFO] Model Type: {model_status['model_type']}")
    port = int(os.environ.get('PORT', 5000))
    print(f"[INFO] Server starting on port {port}")
    app.run(debug=False, host='0.0.0.0', port=port)