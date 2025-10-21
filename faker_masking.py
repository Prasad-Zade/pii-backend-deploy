from faker import Faker
import re

class FakerMasking:
    def __init__(self, seed=42):
        self.fake = Faker()
        Faker.seed(seed)
    
    def mask_text(self, text):
        replacements = {}
        detected = []
        masked = text
        
        # Phone
        for match in re.finditer(r'\b\d{10}\b', text):
            fake_phone = ''.join([str(self.fake.random_digit()) for _ in range(10)])
            replacements[fake_phone] = match.group()
            masked = masked.replace(match.group(), fake_phone, 1)
            detected.append('phone')
        
        # Email
        for match in re.finditer(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', text):
            fake_email = self.fake.email()
            replacements[fake_email] = match.group()
            masked = masked.replace(match.group(), fake_email, 1)
            detected.append('email')
        
        return masked, replacements, detected
    
    def unmask_text(self, text, replacements):
        result = text
        for fake, original in replacements.items():
            result = result.replace(fake, original)
        return result
