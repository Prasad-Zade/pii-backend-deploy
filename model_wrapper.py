"""
Model wrapper to integrate the existing PII Privacy Handler with the Flask backend
"""

import sys
import os
from typing import Dict, Any, Optional
from faker import Faker
from faker_masking import FakerMasking

# Calculate correct model path - the model is in the parent directory of Pii-Security-App
backend_dir = os.path.dirname(__file__)
app_dir = os.path.dirname(backend_dir)  # pii_privacy_handler_app
security_app_dir = os.path.dirname(app_dir)  # Pii-Security-App
amazonq_root = os.path.dirname(security_app_dir)  # AmazonQ
model_path = os.path.join(amazonq_root, 'AmazonQ_modelv1', 'AmazonQ_model')
src_path = os.path.join(model_path, 'src')

# Debug info (commented out to avoid encoding issues)
# print(f"[DEBUG] Model path: {model_path}")
# print(f"[DEBUG] Src path exists: {os.path.exists(src_path)}")

# Add paths to sys.path
if os.path.exists(src_path) and src_path not in sys.path:
    sys.path.insert(0, src_path)
if os.path.exists(model_path) and model_path not in sys.path:
    sys.path.insert(0, model_path)

class ModelWrapper:
    """Wrapper class for the PII Privacy Handler"""
    
    def __init__(self):
        self.handler = None
        self.is_loaded = False
        self.fake = Faker()
        Faker.seed(42)  # For consistent fake data
        self.faker_masker = FakerMasking(seed=42)
        self._initialize_handler()
    
    def _initialize_handler(self):
        """Initialize the PII Privacy Handler"""
        try:
            # Try to load the trained comprehensive model first
            from final_project_model import ComprehensivePIIModel
            self.handler = ComprehensivePIIModel()
            
            # Load pre-trained model if available
            if self.handler.load_model():
                print("[SUCCESS] Trained PII model loaded successfully!")
            else:
                print("[INFO] No pre-trained model found, using rule-based detection")
            
            self.is_loaded = True
            print("[SUCCESS] Comprehensive PII Handler ready!")
            
        except Exception as e:
            print(f"[WARNING] Could not load comprehensive model: {e}")
            try:
                # Fallback to privacy handler
                from privacy_handler import PIIPrivacyHandler
                self.handler = PIIPrivacyHandler()
                self.is_loaded = True
                print("[SUCCESS] Privacy Handler loaded as fallback!")
            except Exception as e2:
                print(f"[ERROR] All handlers failed: {e2}")
                self.is_loaded = False
    
    def process_query(self, user_query: str) -> Dict[str, Any]:
        """Process a user query with PII protection"""
        
        if self.is_loaded and self.handler:
            try:
                # Check if using comprehensive model
                if hasattr(self.handler, 'process_text'):
                    # Use comprehensive model
                    result = self.handler.process_text(user_query)
                    original_pii_map = self._extract_original_pii(result, user_query)
                    
                    # Replace placeholders with fake data
                    anonymized_text = result['masked_text']
                    fake_replacements = {}
                    
                    # Check dependency analysis for each entity
                    dependency_info = result.get('dependency_analysis', {})
                    required_entities = dependency_info.get('required_entities', [])
                    
                    for entity in result.get('pii_entities', []):
                        entity_type = entity.get('type', '').upper()
                        entity_value = entity.get('entity', '')
                        placeholder = f"[{entity.get('type', '')}]"
                        
                        # Check if this entity is required for computation
                        is_required = entity_value in required_entities or entity_type in required_entities
                        
                        if placeholder in anonymized_text:
                            if is_required:
                                # Keep original value for computation
                                anonymized_text = anonymized_text.replace(placeholder, entity_value, 1)
                            else:
                                # Replace with fake value
                                fake_value = self._generate_fake_value(entity_type)
                                anonymized_text = anonymized_text.replace(placeholder, fake_value, 1)
                                fake_replacements[fake_value] = entity_value
                    
                    # Send to LLM
                    llm_response = self._generate_llm_response(anonymized_text, user_query)
                    
                    # Reconstruct LLM response by replacing fake data with original PII
                    import re
                    final_response = llm_response
                    for fake_val, original_val in fake_replacements.items():
                        # Handle formatted versions (e.g., phone with dashes)
                        fake_formatted = re.sub(r'(\d{3})(\d{3})(\d{4})', r'\1-\2-\3', fake_val)
                        final_response = final_response.replace(fake_formatted, original_val)
                        final_response = final_response.replace(fake_val, original_val)
                    
                    # Extract entity information
                    detected_entities = [e['type'] for e in result.get('pii_entities', [])]
                    masked_entities = [e['type'] for e in result.get('pii_entities', []) if e.get('masked', False)]
                    preserved_entities = [e['type'] for e in result.get('pii_entities', []) if not e.get('masked', True)]
                    
                    # Format original phone for matching
                    for fake_val, original_val in list(fake_replacements.items()):
                        if original_val.isdigit() and len(original_val) == 10:
                            original_formatted = f"{original_val[:3]}-{original_val[3:6]}-{original_val[6:]}"
                            final_response = final_response.replace(original_formatted, original_val)
                    
                    return {
                        'original_query': result['original_text'],
                        'masked_query': anonymized_text,
                        'detected_entities': detected_entities,
                        'entities_masked': masked_entities,
                        'entities_preserved': preserved_entities,
                        'context': 'Computational' if result.get('dependency_analysis', {}).get('requires_computation') else 'General',
                        'privacy_preserved': result['masked_entities'] > 0,
                        'llm_response': llm_response,
                        'llm_response_raw': llm_response,
                        'llm_response_reconstructed': final_response,
                        'final_response': final_response,
                        'replacements': fake_replacements,
                        'original_pii_map': original_pii_map
                    }
                
                elif hasattr(self.handler, 'process_query'):
                    # Use privacy handler with Faker enhancement
                    result = self.handler.process_query(user_query)
                    
                    # Enhance with Faker if needed
                    enhanced_result = self._enhance_with_faker(result)
                    
                    return {
                        'original_query': enhanced_result.get('original_query', user_query),
                        'masked_query': enhanced_result.get('masked_query', user_query),
                        'detected_entities': enhanced_result.get('detected_entities', []),
                        'entities_masked': enhanced_result.get('entities_masked', []),
                        'entities_preserved': enhanced_result.get('entities_preserved', []),
                        'context': enhanced_result.get('context', 'General'),
                        'privacy_preserved': enhanced_result.get('privacy_preserved', False),
                        'llm_response': enhanced_result.get('llm_response', enhanced_result.get('final_response', 'Response generated')),
                        'final_response': enhanced_result.get('final_response', enhanced_result.get('llm_response', 'Response generated')),
                        'replacements': enhanced_result.get('replacements', {})
                    }
                
            except Exception as e:
                print(f"[ERROR] Model processing failed: {e}")
                return self._fallback_processing(user_query)
        
        return self._fallback_processing(user_query)
    
    def _apply_faker_replacements(self, model_result: Dict[str, Any]) -> Dict[str, Any]:
        """Apply Faker replacements to model result"""
        import re
        masked_text = model_result['masked_text']
        original_text = model_result['original_text']
        replacements = {}  # fake_value -> placeholder
        fake_to_original = {}  # fake_value -> original_value
        
        # Get original PII from entities
        for entity in model_result.get('pii_entities', []):
            if entity.get('masked', False):
                entity_type = entity.get('type', '')
                original_value = entity.get('entity', '')
                
                # Generate fake value based on type using Faker
                fake_value = self._generate_fake_value(entity_type)
                
                # Replace placeholder with fake value
                placeholder = f"[{entity_type}]"
                if placeholder in masked_text:
                    masked_text = masked_text.replace(placeholder, fake_value, 1)
                    replacements[fake_value] = placeholder
                    fake_to_original[fake_value] = original_value
        
        return {
            'masked_text': masked_text,
            'replacements': replacements,
            'fake_to_original': fake_to_original
        }
    
    def _extract_original_pii(self, model_result: Dict[str, Any], original_query: str) -> Dict[str, str]:
        """Extract original PII values from the query"""
        import re
        pii_map = {}
        
        for entity in model_result.get('pii_entities', []):
            entity_type = entity.get('type', '')
            entity_text = entity.get('entity', '')
            
            if entity_text:
                pii_map[entity_type] = entity_text
        
        return pii_map
    
    def _reconstruct_from_placeholders(self, response: str, original_pii: Dict[str, str]) -> str:
        """Reconstruct response by replacing placeholders with original PII"""
        import re
        reconstructed = response
        
        # Replace placeholders like [NAME], [PHONE], etc. with original values
        placeholder_map = {
            r'\[NAME\]': original_pii.get('NAME', '[NAME]'),
            r'\[PHONE\]': original_pii.get('PHONE', '[PHONE]'),
            r'\[EMAIL\]': original_pii.get('EMAIL', '[EMAIL]'),
            r'\[ADDRESS\]': original_pii.get('ADDRESS', '[ADDRESS]'),
            r'\[AADHAAR\]': original_pii.get('AADHAAR', '[AADHAAR]'),
            r'\[PAN\]': original_pii.get('PAN', '[PAN]'),
        }
        
        for placeholder_pattern, original_value in placeholder_map.items():
            reconstructed = re.sub(placeholder_pattern, original_value, reconstructed, flags=re.IGNORECASE)
            if placeholder_pattern.strip('\\[]') in reconstructed:
                print(f"[RECONSTRUCT] Replaced {placeholder_pattern} with '{original_value}'")
        
        return reconstructed
    
    def _generate_fake_value(self, entity_type: str) -> str:
        """Generate fake value based on entity type using Faker"""
        entity_type_upper = entity_type.upper()
        
        if entity_type_upper in ['NAME', 'FULL_NAME', 'PERSON']:
            return self.fake.name()
        elif entity_type_upper in ['PHONE', 'PHONE_NUMBER']:
            return ''.join([str(self.fake.random_digit()) for _ in range(10)])
        elif entity_type_upper in ['EMAIL', 'EMAIL_ADDRESS']:
            return self.fake.email()
        elif entity_type_upper == 'ADDRESS':
            return self.fake.address().replace('\n', ', ')
        elif entity_type_upper == 'SSN':
            return self.fake.ssn()
        elif entity_type_upper == 'AADHAAR':
            return ''.join([str(self.fake.random_digit()) for _ in range(12)])
        elif entity_type_upper == 'PAN':
            return ''.join([self.fake.random_uppercase_letter() for _ in range(5)]) + ''.join([str(self.fake.random_digit()) for _ in range(4)]) + self.fake.random_uppercase_letter()
        elif entity_type_upper == 'CREDIT_CARD':
            return self.fake.credit_card_number()
        elif entity_type_upper == 'DATE' or entity_type_upper == 'DOB':
            return self.fake.date()
        elif entity_type_upper == 'COMPANY':
            return self.fake.company()
        elif entity_type_upper == 'CITY':
            return self.fake.city()
        elif entity_type_upper == 'COUNTRY':
            return self.fake.country()
        elif entity_type_upper == 'ZIP' or entity_type_upper == 'ZIPCODE':
            return self.fake.zipcode()
        else:
            return self.fake.name()
    
    def _enhance_with_faker(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance privacy handler result with Faker replacements"""
        import re
        
        masked_query = result.get('masked_query', result.get('original_query', ''))
        original_query = result.get('original_query', '')
        replacements = result.get('replacements', {})
        
        # Apply Faker to any remaining hardcoded replacements
        name_patterns = [(r'Alex Johnson', self.fake.name()), (r'John Smith', self.fake.name())]
        phone_patterns = [(r'1234567890', self.fake.phone_number())]
        
        for pattern, fake_replacement in name_patterns + phone_patterns:
            if pattern in masked_query:
                masked_query = masked_query.replace(pattern, fake_replacement)
                replacements[fake_replacement] = pattern
        
        result['masked_query'] = masked_query
        result['replacements'] = replacements
        return result
    
    def _fallback_processing(self, user_query: str) -> Dict[str, Any]:
        """Fallback processing with Faker-based PII masking"""
        # Use FakerMasking utility
        masked_query, replacements, detected_entities = self.faker_masker.mask_text(user_query)
        
        # Generate LLM response
        response = self._generate_fallback_response(user_query, masked_query)
        
        # Reconstruct response with original values
        reconstructed_response = self.faker_masker.unmask_text(response, replacements)
        
        return {
            'original_query': user_query,
            'masked_query': masked_query,
            'detected_entities': detected_entities,
            'entities_masked': detected_entities,
            'entities_preserved': [],
            'context': 'General',
            'privacy_preserved': len(detected_entities) > 0,
            'llm_response': response,
            'final_response': reconstructed_response,
            'replacements': replacements
        }
    
    def _generate_llm_response(self, masked_query: str, original_query: str) -> str:
        """Generate LLM response using Gemini API"""
        
        try:
            import requests
            
            response = requests.post(
                'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=AIzaSyDJb2LPaNY5TVAYCpYmAnNnv0vQcLplQyE',
                headers={'Content-Type': 'application/json'},
                json={
                    'contents': [{
                        'parts': [{'text': masked_query}]
                    }],
                    'generationConfig': {
                        'temperature': 0.7,
                        'maxOutputTokens': 1024
                    }
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'candidates' in data and len(data['candidates']) > 0:
                    return data['candidates'][0]['content']['parts'][0]['text']
        except Exception as e:
            print(f"[INFO] Gemini API error: {e}")
            return self._generate_fallback_response(original_query, masked_query)
        
        return self._generate_fallback_response(original_query, masked_query)
    
    def _generate_fallback_response(self, original: str, masked: str) -> str:
        """Generate fallback response when Gemini API fails"""
        query_lower = original.lower()
        
        # Mathematical operations
        if any(word in query_lower for word in ['sum', 'add', 'calculate', 'digit']):
            import re
            numbers = re.findall(r'\d+', original)
            if numbers:
                number = numbers[0]
                digit_sum = sum(int(d) for d in number)
                return f"The sum of digits in {number} is: {digit_sum}"
        
        # Name operations
        if 'count' in query_lower and 'letter' in query_lower:
            import re
            name_match = re.search(r'name\s+(\w+)', original)
            if name_match:
                name = name_match.group(1)
                count = len([c for c in name if c.isalpha()])
                return f"The name has {count} letters."
        
        # Greetings
        if any(word in query_lower for word in ['my name is', 'i am', 'hello', 'hi']):
            return "Nice to meet you! Your personal information has been protected. How can I help you today?"
        
        return "I understand your request. Your privacy has been preserved. How can I assist you further?"
    
    def get_status(self) -> Dict[str, Any]:
        """Get the status of the model wrapper"""
        model_type = 'Fallback'
        if self.is_loaded and self.handler:
            if hasattr(self.handler, 'process_text'):
                model_type = 'ComprehensivePIIModel'
            elif hasattr(self.handler, 'process_query'):
                model_type = 'PIIPrivacyHandler'
        
        return {
            'model_loaded': self.is_loaded,
            'handler_available': self.handler is not None,
            'model_type': model_type,
            'model_ready': getattr(self.handler, 'model_ready', False) if self.handler else False
        }

# Global instance
model_wrapper = ModelWrapper()

def get_model_wrapper() -> ModelWrapper:
    """Get the global model wrapper instance"""
    return model_wrapper