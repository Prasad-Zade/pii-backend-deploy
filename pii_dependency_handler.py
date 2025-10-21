"""
PII Dependency Handler - Distinguishes between dependent and non-dependent PII
"""

import re
import json
from typing import Dict, Any, List, Tuple
from faker import Faker
import google.generativeai as genai

class PIIDependencyHandler:
    def __init__(self):
        self.fake = Faker()
        self.pii_patterns = {
            'phone': re.compile(r'\b\d{10}\b|\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'),
            'email': re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
            'name': re.compile(r'\b(?:my name is|i am|i\'m|call me)\s+([A-Z][a-z]+)\b', re.IGNORECASE),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'credit_card': re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
        }
        
        self.computation_keywords = [
            'add', 'addition', 'sum', 'calculate', 'multiply', 'divide', 'subtract',
            'total', 'count', 'average', 'mean', 'percentage', 'compute', 'math',
            'arithmetic', 'operation', 'result', 'answer', 'solve'
        ]
        
    def process_query(self, user_query: str, pii_analysis: Dict = None) -> Dict[str, Any]:
        """Process query with dependent/non-dependent PII handling"""
        
        if pii_analysis:
            # Use frontend analysis if provided
            return self._process_with_analysis(user_query, pii_analysis)
        else:
            # Perform backend analysis
            return self._process_with_backend_analysis(user_query)
    
    def _process_with_analysis(self, user_query: str, analysis: Dict) -> Dict[str, Any]:
        """Process using frontend PII analysis"""
        
        original = user_query
        masked = analysis.get('maskedQuery', user_query)
        dependent_entities = analysis.get('dependentEntities', [])
        non_dependent_entities = analysis.get('nonDependentEntities', [])
        all_entities = analysis.get('allEntities', [])
        
        # Generate response based on PII dependency
        if dependent_entities and non_dependent_entities:
            context = "mixed_dependency"
            response = self._generate_mixed_dependency_response(original, masked, dependent_entities)
        elif dependent_entities:
            context = "dependent_only"
            response = self._generate_dependent_response(original, masked, dependent_entities)
        elif non_dependent_entities:
            context = "non_dependent_only"
            response = self._generate_non_dependent_response(masked)
        else:
            context = "no_pii"
            response = self._generate_standard_response(original)
        
        # Reconstruct response by replacing masked entities back
        reconstructed = self._reconstruct_response(response, all_entities, original)
        
        return {
            'original_query': original,
            'masked_query': masked,
            'detected_entities': dependent_entities + non_dependent_entities,
            'dependent_entities': dependent_entities,
            'non_dependent_entities': non_dependent_entities,
            'context': context,
            'privacy_preserved': len(non_dependent_entities) > 0,
            'computation_preserved': len(dependent_entities) > 0,
            'llm_response': response,
            'final_response': reconstructed,
            'privacy_score': analysis.get('privacyScore', 1.0)
        }
    
    def _process_with_backend_analysis(self, user_query: str) -> Dict[str, Any]:
        """Process with backend PII analysis"""
        
        original = user_query
        entities = self._detect_pii_entities(original)
        
        dependent_entities = [e for e in entities if e['is_dependent']]
        non_dependent_entities = [e for e in entities if not e['is_dependent']]
        
        # Create masked version
        masked = self._mask_non_dependent_pii(original, non_dependent_entities)
        
        # Generate response
        if dependent_entities and non_dependent_entities:
            context = "mixed_dependency"
            response = self._generate_mixed_dependency_response(original, masked, dependent_entities)
        elif dependent_entities:
            context = "dependent_only"
            response = self._generate_dependent_response(original, masked, dependent_entities)
        elif non_dependent_entities:
            context = "non_dependent_only"
            response = self._generate_non_dependent_response(masked)
        else:
            context = "no_pii"
            response = self._generate_standard_response(original)
        
        privacy_score = len(non_dependent_entities) / len(entities) if entities else 1.0
        
        return {
            'original_query': original,
            'masked_query': masked,
            'detected_entities': entities,
            'dependent_entities': dependent_entities,
            'non_dependent_entities': non_dependent_entities,
            'context': context,
            'privacy_preserved': len(non_dependent_entities) > 0,
            'computation_preserved': len(dependent_entities) > 0,
            'llm_response': response,
            'final_response': response,
            'privacy_score': privacy_score
        }
    
    def _detect_pii_entities(self, text: str) -> List[Dict]:
        """Detect PII entities and determine dependency"""
        entities = []
        
        for pii_type, pattern in self.pii_patterns.items():
            for match in pattern.finditer(text):
                value = match.group(0)
                is_dependent = self._is_dependent_pii(text, value, pii_type)
                
                entities.append({
                    'value': value,
                    'type': pii_type,
                    'start': match.start(),
                    'end': match.end(),
                    'is_dependent': is_dependent
                })
        
        return entities
    
    def _is_dependent_pii(self, text: str, pii_value: str, pii_type: str) -> bool:
        """Determine if PII is dependent on computation"""
        
        lower_text = text.lower()
        
        # Check for computation keywords
        has_computation = any(keyword in lower_text for keyword in self.computation_keywords)
        
        if not has_computation:
            return False
        
        # For phone numbers, check if used in mathematical context
        if pii_type == 'phone':
            # Look for mathematical operations near the phone number
            phone_index = text.find(pii_value)
            if phone_index != -1:
                context_start = max(0, phone_index - 50)
                context_end = min(len(text), phone_index + len(pii_value) + 50)
                context = text[context_start:context_end].lower()
                
                math_indicators = ['add', 'sum', 'calculate', 'total', 'addition', '+', 'plus']
                return any(indicator in context for indicator in math_indicators)
        
        # Names are typically non-dependent
        if pii_type == 'name':
            return False
        
        # Other PII types are typically non-dependent
        return False
    
    def _mask_non_dependent_pii(self, text: str, non_dependent_entities: List[Dict]) -> str:
        """Mask non-dependent PII entities"""
        masked_text = text
        
        # Sort by start position in reverse order to avoid index shifting
        sorted_entities = sorted(non_dependent_entities, key=lambda x: x['start'], reverse=True)
        
        for entity in sorted_entities:
            mask = self._get_mask_for_type(entity['type'])
            masked_text = masked_text[:entity['start']] + mask + masked_text[entity['end']:]
        
        return masked_text
    
    def _get_mask_for_type(self, pii_type: str) -> str:
        """Get appropriate mask for PII type"""
        masks = {
            'name': '[NAME]',
            'phone': '[PHONE]',
            'email': '[EMAIL]',
            'ssn': '[SSN]',
            'credit_card': '[CREDIT_CARD]'
        }
        return masks.get(pii_type, '[PII]')
    
    def _generate_mixed_dependency_response(self, original: str, masked: str, dependent_entities: List[Dict]) -> str:
        """Generate response for mixed dependency scenario"""
        
        # Extract numbers for calculation if present
        if any(entity['type'] == 'phone' for entity in dependent_entities):
            phone_numbers = [entity['value'] for entity in dependent_entities if entity['type'] == 'phone']
            if phone_numbers and any(keyword in original.lower() for keyword in ['add', 'sum', 'calculate']):
                try:
                    # Simple digit sum calculation
                    total = sum(int(digit) for phone in phone_numbers for digit in phone if digit.isdigit())
                    return f"I've protected your personal information while keeping the phone number for calculation. The sum of all digits in {phone_numbers[0]} is: {total}"
                except:
                    pass
        
        return self._generate_standard_response(masked)
    
    def _generate_dependent_response(self, original: str, masked: str, dependent_entities: List[Dict]) -> str:
        """Generate response for dependent PII scenario"""
        
        # Handle phone number calculations
        phone_entities = [e for e in dependent_entities if e['type'] == 'phone']
        if phone_entities and any(keyword in original.lower() for keyword in ['add', 'sum', 'calculate']):
            phone = phone_entities[0]['value']
            try:
                digit_sum = sum(int(digit) for digit in phone if digit.isdigit())
                return f"I've kept your phone number for the calculation. The sum of all digits in {phone} is: {digit_sum}"
            except:
                pass
        
        return self._generate_standard_response(original)
    
    def _generate_non_dependent_response(self, masked: str) -> str:
        """Generate response for non-dependent PII scenario"""
        return self._generate_standard_response(masked)
    
    def _reconstruct_response(self, response: str, entities: List[Dict], original_text: str) -> str:
        """Reconstruct response by replacing masked PII with original values"""
        reconstructed = response
        
        # Create mapping of masked values to original values
        for entity in entities:
            if not entity.get('isDependent', False):
                original_value = entity.get('value', '')
                entity_type = entity.get('type', '')
                
                # Get the mask pattern
                mask_patterns = {
                    'name': r'\[NAME\]|John|Alice|Bob|Sarah|Mike|Emma',
                    'phone': r'\[PHONE\]|555\d{7}',
                    'email': r'\[EMAIL\]|\w+@(?:example|test|demo)\.com',
                }
                
                pattern = mask_patterns.get(entity_type)
                if pattern and original_value:
                    reconstructed = re.sub(pattern, original_value, reconstructed, count=1)
        
        return reconstructed
    
    def _generate_standard_response(self, text: str) -> str:
        """Generate standard response using Gemini API"""
        import requests
        
        query = text.lower()
        
        # Handle math operations locally
        if any(math_word in query for math_word in ['add', 'sum', 'calculate']):
            numbers = re.findall(r'\d+', text)
            if len(numbers) >= 2:
                try:
                    result = sum(int(num) for num in numbers)
                    return f"The sum of {' + '.join(numbers)} is: {result}"
                except:
                    pass
        
        # Call Gemini API using HTTP
        print(f"[DEBUG] Calling Gemini for: {text[:50]}")
        api_key = 'AIzaSyAJpAxoKWc9biprobj_KXP0hxCRoByAEFo'
        url = f'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}'
        
        try:
            response = requests.post(url, json={
                'contents': [{'parts': [{'text': text}]}]
            }, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                result = data['candidates'][0]['content']['parts'][0]['text']
                print(f"[DEBUG] Full response: {result}")
                return result
            else:
                print(f"[ERROR] API {response.status_code}: {response.text}")
        except Exception as e:
            print(f"[ERROR] API failed: {e}")
        
        print("[DEBUG] Using fallback response")
        return "I understand your message. How can I help you further while ensuring your privacy is protected?"