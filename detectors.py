from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_analyzer.predefined_recognizers import PhoneNumberRecognizer
import re

# Presidio Setup (PII) 
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# 3 Custom Recognizers
class ApiKeyRecognizer:
    def __init__(self):
        self.name = "API_KEY"
        self.score = 0.95

    def load(self): pass
    def analyze(self, text):
        patterns = [r'sk-[a-zA-Z0-9]{20,}', r'pk_live_[a-zA-Z0-9]{20,}', r'AKIA[0-9A-Z]{16}']
        results = []
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                results.append(RecognizerResult(entity_type=self.name, start=match.start(), end=match.end(), score=self.score))
        return results

class InternalIDRecognizer:
    def __init__(self):
        self.name = "INTERNAL_ID"
        self.score = 0.85

    def load(self): pass
    def analyze(self, text):
        pattern = r'\b(CSC|FA|SP|CIIT)\d{2}-\d{4}\b'
        results = []
        for match in re.finditer(pattern, text):
            results.append(RecognizerResult(entity_type=self.name, start=match.start(), end=match.end(), score=self.score))
        return results

api_key_rec = ApiKeyRecognizer()
internal_id_rec = InternalIDRecognizer()
pk_phone = PhoneNumberRecognizer(supported_entities=["PHONE_NUMBER"])
pk_phone.score = 0.92

analyzer.registry.add_recognizer(api_key_rec)
analyzer.registry.add_recognizer(internal_id_rec)
analyzer.registry.add_recognizer(pk_phone)

custom_analyzer = analyzer

# IMPROVED INJECTION SCORING 
def injection_score(text: str) -> float:
    """Pure Python + Regex based Advanced Scoring (No NLP library used)"""
    if not text:
        return 0.0
    
    text_lower = text.lower().strip()
    score = 0.0

    strong_phrases = {
        "ignore previous instructions": 0.85,
        "ignore all previous": 0.80,
        "forget all rules": 0.85,
        "forget previous instructions": 0.80,
        "jailbreak": 0.90,
        "dan mode": 0.95,
        "do anything now": 0.90,
        "developer mode": 0.85,
        "system prompt": 0.75,
        "reveal your instructions": 0.80,
        "disregard previous": 0.75,
        "override previous": 0.80,
        "new system prompt": 0.85,
        "you are now": 0.70,
        "act as if": 0.65,
        "bypass all restrictions": 0.90,
        "remove all safety": 0.85,
        "unrestricted mode": 0.85,
        "evil mode": 0.80,
        "maximum truth": 0.70,
        "ignore safety guidelines": 0.85,
        "you must follow": 0.75,
        "from now on you are": 0.80,
        "new instructions": 0.70,
        "roleplay as": 0.65,
        "hypothetical scenario": 0.65,
    }

    # Phrase checking
    for phrase, points in strong_phrases.items():
        if phrase in text_lower:
            score += points

            if text_lower.startswith(phrase[:20]):
                score += 0.15

    # Regex for common variations
    if re.search(r'ign0re|1gnore|f0rget|jailbr3ak|d3v', text_lower):
        score += 0.60

    if len(text) > 250:
        score += 0.30

    # Normalize (max 1.0)
    return round(min(score, 1.0), 2)